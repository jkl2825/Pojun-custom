package agent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// 假写回源：测试里手动推进写回计数。
type fakeWrites struct {
	mu sync.Mutex
	w  WriteCounts
}

func (f *fakeWrites) get() WriteCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w
}

func (f *fakeWrites) addFacts(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.Facts += n
}

// 起跑宽限期要能跳过——测试不该真的等 3 分钟。
// 这里直接改 start，让「已运行时长」超过宽限期。
func ageStopper(s *idleStopper, d time.Duration) {
	s.mu.Lock()
	s.start = time.Now().Add(-d)
	s.mu.Unlock()
}

// newStopperForTest 造一个「只按轮数判定」的 stopper（时间窗置零）。
// 生产默认要求轮数达标且距上次写回超过 12 分钟；测试不该真的等 12 分钟，
// 所以这里把窗口关掉，只验证轮数/写回重置/宽限期这些逻辑。
// 时间窗本身另有专门用例（TestIdleStopWindowBlocksEarlyTrip）。
func newStopperForTest(w func() WriteCounts) *idleStopper {
	s := newIdleStopper(w)
	s.window = 0
	return s
}

// 连续无写回达到阈值时必须要求收场。
func TestIdleStopFiresAfterNoWrites(t *testing.T) {
	fw := &fakeWrites{}
	s := newStopperForTest(fw.get)
	ageStopper(s, time.Hour) // 越过起跑宽限期

	// 前两轮：还没到阈值。
	for i := 0; i < idleStopRounds-1; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("第 %d 轮就要求收场了（阈值 %d 未到）", i+1, idleStopRounds)
		}
	}
	prevent, reason := s.check()
	if !prevent {
		t.Fatalf("连续 %d 轮无写回后应要求收场", idleStopRounds)
	}
	if !strings.Contains(reason, "无写回") {
		t.Errorf("收场原因应说明无写回: %q", reason)
	}
}

// 有写回就重置计数——持续产出的 worker 永远不该被收。
// 这是「深度优先不受影响」这条设计的关键。
func TestIdleStopResetsOnWrite(t *testing.T) {
	fw := &fakeWrites{}
	s := newStopperForTest(fw.get)
	ageStopper(s, time.Hour)

	// 连续两轮无写回。
	s.check()
	s.check()
	// 第三轮有写回 → 计数归零。
	fw.addFacts(1)
	if prevent, _ := s.check(); prevent {
		t.Fatal("有写回时不该要求收场")
	}
	// 再连续 idleStopRounds 轮才该收。
	for i := 0; i < idleStopRounds-1; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("写回后计数应归零，第 %d 轮就收了", i+1)
		}
	}
	if prevent, _ := s.check(); !prevent {
		t.Fatal("再次连续无写回到阈值后应要求收场")
	}
}

// 起跑宽限期内不收场——worker 刚起手的前几轮可能在做准备工作。
func TestIdleStopHasGracePeriod(t *testing.T) {
	fw := &fakeWrites{}
	s := newStopperForTest(fw.get)
	// 刚起跑（start = now），宽限期没过。
	for i := 0; i < idleStopRounds+3; i++ {
		if prevent, _ := s.check(); prevent {
			t.Fatalf("起跑宽限期内不该收场（第 %d 轮）", i+1)
		}
	}
}

// 第一次触发是「提示模型写回」，不是直接终止——
// 直接终止会把模型手里「探到了但还没写回」的东西全丢掉。
func TestIdleStopNudgesBeforeStopping(t *testing.T) {
	fw := &fakeWrites{}
	inner := &spyHook{}
	h := wrapIdleStop(inner, fw.get, nil)
	h.stop.window = 0 // 测试不等时间窗
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	// 跑到达阈值的那一轮：这次调用会返回 blocking（提示），不是 prevent。
	// 阈值是第 idleStopRounds 轮，所以前 idleStopRounds-1 轮都不触发。
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
		if i < idleStopRounds-1 && (prevent || len(blocking) > 0) {
			t.Fatalf("第 %d 轮不该触发（阈值 %d）", i+1, idleStopRounds)
		}
	}
	if prevent {
		t.Fatal("第一次触发应先提示模型写回，不该直接终止")
	}
	if len(blocking) == 0 {
		t.Fatal("应返回一条 blocking 提示")
	}
	if !strings.Contains(blocking[0], "写回") {
		t.Errorf("提示语应说明要写回: %q", blocking[0])
	}
	// 提示之后还不停 → 真的收场。
	prevent, _, msg := h.Stop(ctx, nil)
	if !prevent {
		t.Fatal("提示之后仍不收场，应真的终止")
	}
	if msg == "" {
		t.Error("终止时应带收场原因")
	}
}

// 提示之后模型确实写回了 → 不该再收场（模型在正常收尾）。
func TestIdleStopStopsNudgingAfterWrite(t *testing.T) {
	fw := &fakeWrites{}
	h := wrapIdleStop(nil, fw.get, nil)
	h.stop.window = 0 // 测试不等时间窗
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
	}
	if prevent || len(blocking) == 0 {
		t.Fatal("第一次触发应是提示")
	}
	// 模型响应提示，写回了结果。
	fw.addFacts(1)
	prevent, _, _ = h.Stop(ctx, nil)
	if prevent {
		t.Fatal("模型写回后不该再收场")
	}
}

// inner（拦截管控）说要停就必须停——idle-stop 不能覆盖管控决定。
func TestIdleStopRespectsInnerStop(t *testing.T) {
	// spyHook.Stop 恒返回 false（它只统计调用次数），这里用一个会真正
	// 喊停的 inner。
	inner := &blockingHook{prevent: true, msg: "平台管控拦截"}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	h.stop.window = 0 // 测试不等时间窗
	ageStopper(h.stop, time.Hour)

	prevent, _, msg := h.Stop(context.Background(), nil)
	if !prevent {
		t.Fatal("inner 的停止决定必须透传")
	}
	if msg != "平台管控拦截" {
		t.Errorf("inner 的消息应透传: %q", msg)
	}
	if inner.stopCalls != 1 {
		t.Errorf("inner 应被调用一次,实际 %d", inner.stopCalls)
	}
}

// blockingHook 是一个会按预设返回的 hook（用于验证内层的停止决定透传）。
type blockingHook struct {
	prevent   bool
	msg       string
	stopCalls int
}

func (b *blockingHook) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	return false, "", nil
}
func (b *blockingHook) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (b *blockingHook) Stop(context.Context, []llm.Message) (bool, []string, string) {
	b.stopCalls++
	return b.prevent, nil, b.msg
}

// inner 说「继续」时，idle-stop 的判断仍然生效（两层独立）。
func TestIdleStopAppliesWhenInnerAllows(t *testing.T) {
	inner := &spyHook{}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	h.stop.window = 0 // 测试不等时间窗
	ageStopper(h.stop, time.Hour)

	ctx := context.Background()
	var prevent bool
	var blocking []string
	for i := 0; i < idleStopRounds; i++ {
		prevent, blocking, _ = h.Stop(ctx, nil)
	}
	if prevent {
		t.Fatal("第一次触发应是提示")
	}
	if len(blocking) == 0 {
		t.Fatal("应有 blocking 提示")
	}
}

// 工具调用必须原样透传给 inner——idle-stop 是旁路，不能影响拦截。
func TestIdleStopForwardsToolHooks(t *testing.T) {
	inner := &spyHook{}
	fw := &fakeWrites{}
	h := wrapIdleStop(inner, fw.get, nil)
	h.stop.window = 0 // 测试不等时间窗
	ctx := context.Background()

	h.PreToolUse(ctx, "Bash", []byte(`{"command":"ls"}`))
	h.PostToolUse(ctx, "Bash", []byte(`{}`), []byte("ok"), false)

	if inner.preCalls != 1 || inner.postCalls != 1 {
		t.Fatalf("工具事件未透传: pre=%d post=%d", inner.preCalls, inner.postCalls)
	}
}

// 写回函数为 nil 时不能 panic（防御性：ToolSet 总是有的，但别依赖它）。
func TestIdleStopNilWritesSafe(t *testing.T) {
	s := newStopperForTest(nil)
	ageStopper(s, time.Hour)
	for i := 0; i < idleStopRounds; i++ {
		s.check()
	}
	if prevent, _ := s.check(); !prevent {
		t.Fatal("nil 写回源时也应能判定收场")
	}
}

// 收场原因要写清「连续几轮无写回」——planner 靠它区分
// 「被墙钟掐断」和「这个方向本身没东西了」，这两种在决策上完全相反。
func TestIdleStopReasonExplainsWhy(t *testing.T) {
	fw := &fakeWrites{}
	s := newStopperForTest(fw.get)
	ageStopper(s, time.Hour)
	for i := 0; i < idleStopRounds; i++ {
		s.check()
	}
	_, reason := s.check()
	for _, want := range []string{"连续", "无写回", "产出率"} {
		if !strings.Contains(reason, want) {
			t.Errorf("收场原因缺少 %q: %q", want, reason)
		}
	}
}

// 时间窗未到：轮数再多也不收——保护「慢但有效」的远程利用。
//
// 任务 333 的教训：一条 timeout 260s 的远程利用链，两三轮就是十几分钟，
// 轮数早就过阈值但它显然没空转。判据必须有时间维度。
func TestIdleStopWindowBlocksEarlyTrip(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get) // 生产默认窗口
	ageStopper(s, time.Hour)    // 越过起跑宽限期

	for i := 0; i < idleStopRounds+2; i++ {
		s.advance()
	}
	if prevent, reason := s.peek(); prevent {
		t.Fatalf("距上次写回不足一个时间窗，不该判空转: %s", reason)
	}
}

// 硬上限：连续调用次数极多时，即使时间窗未到也判空转（防「快速失败空转」）。
func TestIdleStopHardRoundsIgnoresWindow(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	s.window = time.Hour // 时间窗故意拉长
	ageStopper(s, time.Hour)

	for i := 0; i < idleStopHardRounds; i++ {
		s.advance()
	}
	if prevent, _ := s.peek(); !prevent {
		t.Fatalf("连续 %d 轮无写回应触发硬上限", idleStopHardRounds)
	}
}

// idleStopMessage 必须说清三件事：为什么停、要做什么、不要做什么。
// 措辞直接影响模型的行为：说「预算耗尽被终止」会让模型以为被惩罚，
// 于是倾向于把没验证的猜测也写成结论。
func TestIdleStopMessageContent(t *testing.T) {
	for _, want := range []string{"新发现", "insert_assets", "record_fact", "不要"} {
		if !strings.Contains(idleStopMessage, want) {
			t.Errorf("收场提示缺少 %q: %s", want, idleStopMessage)
		}
	}
}

// 提示语里不能出现「预算耗尽」这类措辞——那会让模型误以为是被惩罚，
// 从而把没验证的猜测也写成结论。
func TestIdleStopMessageDoesNotSayBudget(t *testing.T) {
	for _, bad := range []string{"预算耗尽", "被终止", "超时"} {
		if strings.Contains(idleStopMessage, bad) {
			t.Errorf("收场提示不应含 %q: %s", bad, idleStopMessage)
		}
	}
}

// 确认 idleStopHooks 满足 harness.HookRunner 接口。
var _ = func(h *idleStopHooks) harness.HookRunner { return h }
