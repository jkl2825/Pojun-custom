package db

import (
	"net/url"
	"strings"
)

// IsTestDatabase 判断 DSN 指向的库名是否以 `_test` 结尾。
//
// 为什么需要它：db / agent / server 三个包的测试会真的创建 task、llm_profile、
// exploration 等持久对象，只会删自己造的那几条，不做事务回滚。2026-11-05 一次
// 全量 `go test ./db/` 直连生产库，留下 34 个状态为 running 的假任务和 12 个
// 测试 profile（其中一个抢了 is_default，导致引擎起不来 provider）。
//
// 所以三个包的 TestMain 都用它做闸门：不是 `*_test` 库就整体跳过，除非显式
// 设置 POJUN_TEST_ALLOW_PROD=1。
//
// 只认后缀而不是白名单，是为了让每个人都用各自的库名（pojun_test、
// pojun_ci_test）都能跑，同时挡住"误连生产库"这个最常见的错。
func IsTestDatabase(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	name := strings.TrimPrefix(u.Path, "/")
	return strings.HasSuffix(name, "_test")
}
