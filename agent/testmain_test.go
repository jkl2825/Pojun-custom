package agent

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/chu0119/pojun/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// agent test suite so cross-package DELETE cleanup races with db/server
// packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	// 生产库闸门（2026-11-05）：这些用例会真的建 task/profile/exploration，
	// 直连生产库会留下脏数据（曾留下 34 个 running 假任务）。详见 db.IsTestDatabase。
	if os.Getenv("POJUN_TEST_ALLOW_PROD") != "1" && !db.IsTestDatabase(dsn) {
		fmt.Fprintln(os.Stderr, "[agent tests] 拒绝在非测试库上运行；用 DSN 指向 *_test 库，或设 POJUN_TEST_ALLOW_PROD=1")
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
