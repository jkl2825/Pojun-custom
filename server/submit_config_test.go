package server

import "testing"

// TestNormalizeSubmitConfig 锁住提交通道的准入条件。
//
// 这些规则的意义不是"帮用户把配置填对"，而是防止一个**注定失败**的通道
// 被装上：装上之后每轮 worker 都会拿到 submit_flag，每次提交都白跑一趟，
// 而现象是"提交没反应"，排查成本极高。
func TestNormalizeSubmitConfig(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want int // 规范化后的字段数，-1 表示应报错
	}{
		{"空配置等于没有通道", nil, 0},
		{"只给 url", map[string]string{"url": "http://1.2.3.4:8080/api/submit"}, 1},
		{"完整配置", map[string]string{
			"url": "https://t.local/api/submit", "agent": "a1", "token": "t1", "display_name": "n",
		}, 4},
		{"缺 url", map[string]string{"agent": "a1", "token": "t1"}, -1},
		{"url 无协议", map[string]string{"url": "1.2.3.4/api"}, -1},
		{"只有 token 没有 agent", map[string]string{"url": "http://t.local/x", "token": "t1"}, -1},
		{"只有 agent 没有 token", map[string]string{"url": "http://t.local/x", "agent": "a1"}, -1},
		{"空白值被丢弃", map[string]string{"url": " http://t.local/x ", "agent": "  "}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeSubmitConfig(c.in)
			if c.want < 0 {
				if err == nil {
					t.Fatalf("期望报错，实际通过：%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望通过，实际报错：%v", err)
			}
			if len(got) != c.want {
				t.Fatalf("字段数=%d，期望 %d（%+v）", len(got), c.want, got)
			}
		})
	}
}
