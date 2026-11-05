package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestIntentCancelWaitsForRunningWorkerBeforeCleanup(t *testing.T) {
	for _, mode := range []string{"soft", "hard"} {
		t.Run(mode, func(t *testing.T) {
			m, err := NewManager(t.TempDir(), "")
			if err != nil {
				t.Skipf("postgres 不可用 (%v)", err)
			}
			defer m.Close()
			task, err := m.CreateTask("cancel running", "等待写回完成再清理", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
			iid, err := task.Store.AddIntent(map[string]any{"summary": "运行中意图"}, 1, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			if claimed, err := task.Store.ClaimIntent(iid, "work#1"); err != nil || !claimed {
				t.Fatalf("领取: claimed=%v err=%v", claimed, err)
			}
			s := newAdmissionTestServer(m, nil)
			workCtx, workCancel := context.WithCancelCause(context.Background())
			defer workCancel(nil)
			s.engine.registerWork(iid, workCancel)
			requestCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			results := make(chan error, 1)
			go func() {
				_, err := s.applyIntentControl(requestCtx, task, iid, "cancel", "取消测试", mode)
				results <- err
			}()
			select {
			case <-workCtx.Done():
			case <-requestCtx.Done():
				t.Fatal("取消请求未通知 worker")
			}
			select {
			case err := <-results:
				t.Fatalf("worker 完成写回前控制请求已返回: %v", err)
			default:
			}
			action, complete := s.engine.detachWork(iid)
			if action != "cancel" {
				complete(nil)
				t.Fatalf("控制动作=%q", action)
			}
			changed, err := task.Store.CompareAndSetIntentState(iid, "running", "paused")
			if err != nil || !changed {
				complete(err)
				t.Fatalf("worker 最终状态: changed=%v err=%v", changed, err)
			}
			complete(nil)
			if err := <-results; err != nil {
				t.Fatal(err)
			}
			node, err := task.Store.GetNode(iid)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "hard" && node != nil {
				t.Fatal("硬删除未清理已停止的意图")
			}
			if mode == "soft" && (node == nil || node.State != db.StateIntentDeleted) {
				t.Fatalf("软删除状态=%+v", node)
			}
		})
	}
}

func TestWorkerControlRoutes(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()

	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	token, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"action":"pause"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// The single-worker route is still registered and reaches its JSON handler.
	single := request("/api/tasks/missing/intents/1/control")
	if single.Code != http.StatusNotFound || !strings.Contains(single.Body.String(), `"error":"task not found"`) {
		t.Fatalf("single control route unavailable: status=%d body=%s", single.Code, single.Body.String())
	}

	// The former batch route must fall through the mux instead of reaching a task handler.
	batch := request("/api/tasks/missing/intents/control/batch")
	if batch.Code != http.StatusNotFound || !strings.Contains(batch.Body.String(), "404 page not found") {
		t.Fatalf("batch control route still registered: status=%d body=%s", batch.Code, batch.Body.String())
	}
}
