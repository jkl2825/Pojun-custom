package db

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// db test suite. Packages agent and server hold the same lock, so parallel
// `go test ./...` runs serialize across packages on the shared dev DB and
// avoid cross-package cleanup races (e.g. DELETE FROM assets WHERE id > X
// from one package deleting assets created by another).
//
// 2026-11-05 追加生产库闸门：整个 db 包的用例都会跳过，除非 DSN 指向
// `*_test` 库或显式设置了 POJUN_TEST_ALLOW_PROD=1。原因见 testDSN 的注释——
// 一次全量测试直连生产库，留下 34 个 running 假任务和 12 个测试 profile。
func TestMain(m *testing.M) {
	dsn, _, err := DSN()
	if err != nil {
		// No DB configured — tests that need PG will skip themselves.
		os.Exit(m.Run())
	}
	if os.Getenv("POJUN_TEST_ALLOW_PROD") != "1" && !IsTestDatabase(dsn) {
		fmt.Fprintf(os.Stderr,
			"[db tests] 拒绝在非测试库上运行（%s）。\n"+
				"  这些用例会真的创建 task/profile/exploration，直连生产库会留下脏数据。\n"+
				"  改用测试库：POJUN_PG_DSN='postgres://...:5432/pojun_test?sslmode=disable' go test ./db/\n"+
				"  或确需在生产库上跑：POJUN_TEST_ALLOW_PROD=1 go test ./db/\n",
			redactDSN(dsn))
		os.Exit(0)
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	os.Exit(m.Run())
}
