package db

import "fmt"

// 收官对账（2026-11-05，借鉴 sapper-v2 的 endgame 纪律）。
//
// sapper 在最后一段停止开新局，专做三件事：确认已捕获的都提交了、关闭平台实例、
// 写总结。这里要修正一个认知——它战报说这一步"挖出 4 分"，但事件日志显示最后
// 一次计分在 18:57，之后 66 分钟零计分。**对账的价值不是翻盘，是防漏**：
// 已经拿到手的东西别在收尾时丢掉。
//
// 我们的等价物是三类：
//  1. 没跑完的方向（open）——收尾时直接消失，交付物里必须写清"哪些没测"；
//  2. 撞墙停下的方向（blocked）——要带上原因，否则客户看到的是"没发现"；
//  3. 没有证据的 finding——我们自己就有 28 条历史 finding 无流量证据的教训。
//
// 只读，不改任何状态：收尾阶段改状态风险远大于收益。

// SettlementReconciliation 是一次收尾对账的快照。
type SettlementReconciliation struct {
	OpenIntents     int // 从未执行的方向
	BlockedIntents  int // 撞墙停放的方向
	TotalFindings   int
	NoEvidence      int // 证据字段为空的 finding
	ExecutedIntents int // 已执行（done/stopped/exhausted）的方向
}

// ReconcileForSettle 读取本次任务的对账数据。
func (s *ExplorationStore) ReconcileForSettle(taskID int64) (SettlementReconciliation, error) {
	var r SettlementReconciliation
	err := s.db.QueryRow(`SELECT
  count(*) FILTER (WHERE kind='intent' AND state='open'),
  count(*) FILTER (WHERE kind='intent' AND state='blocked'),
  count(*) FILTER (WHERE kind='intent' AND state IN ('done','stopped','exhausted'))
FROM exploration_nodes WHERE exploration_id=$1`, s.expID).
		Scan(&r.OpenIntents, &r.BlockedIntents, &r.ExecutedIntents)
	if err != nil {
		return r, err
	}
	err = s.db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE COALESCE(btrim(evidence),'')='')
FROM findings WHERE task_id=$1`, taskID).Scan(&r.TotalFindings, &r.NoEvidence)
	return r, err
}

// Summary 把对账结果压成一行，直接进 activity/日志。
func (r SettlementReconciliation) Summary() string {
	parts := []string{
		fmt.Sprintf("已执行方向 %d 条", r.ExecutedIntents),
		fmt.Sprintf("未执行方向 %d 条", r.OpenIntents),
		fmt.Sprintf("停放 %d 条", r.BlockedIntents),
		fmt.Sprintf("finding %d 个", r.TotalFindings),
	}
	if r.NoEvidence > 0 {
		parts = append(parts, fmt.Sprintf("其中 %d 个无证据（交付前需补证或标注）", r.NoEvidence))
	}
	return "收官对账：" + joinComma(parts)
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "，"
		}
		out += x
	}
	return out
}
