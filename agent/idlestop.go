package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// 无增量自动收尾（idle-stop）：worker 连续若干轮没有写回任何东西时，
// 主动结束这一轮 run，而不是等墙钟预算耗尽被强行掐断。
//
// ## 为什么需要它
//
// 现状是「限定目标 → 限时 → 到点强制总结 → planner 重新派」。这个结构有三个
// 实测出来的问题：
//
//  1. **收尾是被动的**：worker 不知道「该收手了」，只知道「时间快到了赶紧写」。
//     线上实测意图 summary 平均 737 字、最长 2267 字——它把有东西都倒出来，
//     因为死线强制它这么做。
//  2. **耗尽远多于完成**：线上意图终态分布是 done 18 / exhausted 99 /
//     blocked 82。exhausted 是 done 的 5.5 倍，说明绝大多数探测是**被掐断的**，
//     不是跑完的。
//  3. **接续链正反馈**：planner 看到 exhausted 时的指令是「接近突破被预算掐 →
//     派『接上次进度继续』」。但「接近突破」由 planner 判断，而 planner 只看得到
//     一句 summary 和 trace——summary 越长，planner 越觉得「快到了，再给一次
//     机会」。长 summary → 续派 → 更长的意图 → 更长的 summary。
//
// 线上实测到一条三代接续的链：#635 → #578 → #660，摘要在说「接续两次被后端
// 重启打断的 #635/#578 继续攻 ZStack 管理 API 凭据这条皇冠链（#635 上一轮已
// 跑到 56 轮/28 分钟）」。
//
// ## 判据：产出率，不是时长
//
// 用「连续 N 轮没有写回任何 fact/asset/finding」作为收尾判据，而不是用时长。
// 时长是噪声——一个 worker 连着 10 轮扫同一批端口不写回，那是没产出；但一个
// worker 每轮都在写回新资产，它跑满 30 分钟也不该被砍。
//
// 产出率直接对应「这个方向还有没有价值」，而时长不。
//
// ## 挂在哪个钩子上（2026-10-21 修正）
//
// 原先只挂在 **Stop** hook 上，注释写的是「harness.HookRunner.Stop 在每个
// assistant 回合之后被调用」——**这个前提是错的**。SDK 实际只在
// `len(toolUses) == 0`（模型该轮没调任何工具）时才调 Stop
// （harness/query.go:466）。于是：
//
//	持续干活的 worker（每轮都调工具）→ Stop 永远不被调用
//	→ 空转判据形同虚设
//
// 线上实测：任务 5 的 5 个意图跑了 34~58 轮、**一次写回都没有**，却一直
// 不被收场；journal 里「无增量自动收场」一条都没有。
//
// 现在**两处都挂**：
//   - **PreToolUse**（harness/tools.go:78，每次工具调用前都调）——主判据。
//     达到阈值就**阻止本次工具调用**并把「请把已确认的写回并收手」回传给
//     模型（与 steer_work 的纠偏机制同一个模式：block=true + message）。
//     一个持续干活的 worker 走的正是这条路，所以它收得住。
//   - **Stop**（模型该轮没调工具时）——保留，覆盖「模型只是想说话」的场景。
//
// ## 为什么不影响「深度优先」
//
// 深度优先（发现高价值入口就往深打穿）与「限定时长」是直接冲突的。这里的
// 判据绕开了这个冲突：**只在该方向已经不再产出时才收**。一个持续产出的
// worker 不会被这个机制打断——深度探索不受影响，被打断的只有空转。

// idleStopDefaults 是无增量收尾的默认参数。
const (
	// idleStopRounds 是「连续多少次工具执行没有写回」的**下限**条件之一。
	//
	// 2026-11-05 调整：原值 3 太紧，实测把正常利用链误杀。任务 333 一晚触发
	// 218 次、覆盖 122 个意图（占已完成意图三分之一），finding 产出在 15 点后
	// 从 20/小时掉到 4/小时。根因是口径：一次工具执行算「一轮」，而一条利用链的
	// 正常节奏是「写脚本 → 跑 → 解析回显 → 调整 → 再跑」，一个逻辑步骤就要
	// 4-10 次工具执行，3 次必然误伤。
	//
	// 现在改成**双条件**：轮数达标 **且**（距上次写回超过 idleStopWindow
	// **或** 轮数达到 idleStopHardRounds）。单纯「连着调几次工具」不再触发。
	idleStopRounds = 10

	// idleStopWindow 是「距上次写回的时间」下限。
	//
	// 为什么需要时间维度：轮数只反映「调了多少次」，不反映「花了多久」。
	// 一个正在跑 timeout 260s 远程利用脚本的 worker，两三轮就是十几分钟，
	// 轮数早就够了但它显然没空转。时间窗让「慢但有效」的探测不被误判。
	idleStopWindow = 12 * time.Minute

	// idleStopHardRounds 是**兜底硬上限**：无论时间窗是否满足，连续这么多次
	// 工具执行都没有写回，就认定空转。防止「频繁失败但每次很快」的循环靠时间
	// 窗逃过判据。
	idleStopHardRounds = 30

	// idleStopMinElapsed 是「至少已经跑了多久才允许按无增量收场」。
	//
	// 存在的意义：worker 刚起手的前几轮可能在做准备工作（建工作目录、读前期
	// 事实、拉取目标信息），这些轮次不写回是正常的。给它一段起跑宽限期，
	// 避免开局就被判定为空转。
	idleStopMinElapsed = 3 * time.Minute
)

// idleStopper 在一轮 worker run 内跟踪「连续无写回的轮数」，到阈值就要求收场。
//
// 计数口径：**每一次 Stop 回调算一轮**。Stop 在每个 assistant 回合后调用，
// 所以一轮 ≈ 一次「模型思考 + 一批工具调用」。
type idleStopper struct {
	// writes 指向本 run 的写回计数器（ToolSet.Writes 的来源）。
	writes func() WriteCounts

	// rounds 是连续没有写回的轮数。
	rounds int
	// lastWrites 是上一次看到的写回总量，用来判断「这一轮有没有新增」。
	lastWrites int
	// start 是本 run 的起点，用于起跑宽限期。
	start time.Time
	// lastWriteAt 是最近一次写回的时刻，用于「时间窗」条件。
	//
	// 与 rounds 互补：rounds 高但时间窗未到 → 说明它在跑慢动作（远程利用、
	// 大字典扫描），不该收；时间窗到了但 rounds 未到 → 说明它调工具不频繁，
	// 也不该按「空转」收。
	lastWriteAt time.Time
	// window 是时间窗阈值。留成字段（而不是直接用常量）是为了单测能把
	// 时间窗置零、只验证轮数逻辑。
	window time.Duration
	// stopped 标记是否已经要求过收场（只要求一次）。
	stopped bool
	// nudged 记录是否已经给过「请写回并收手」的提示。提示过一次后若仍不停，
	// 下一次才真收场。跟 idleStopHooks.nudged 是同一件事的两份计数——stopper
	// 里的这份用于「有写回后重置」（恢复后允许再提示一次）。
	nudged bool
	// mu 保护并发访问（Stop 可能与工具执行并发）。
	mu sync.Mutex
	// reason 记录收场原因，落日志/落库用。
	reason string
}

func newIdleStopper(writes func() WriteCounts) *idleStopper {
	now := time.Now()
	return &idleStopper{writes: writes, start: now, lastWriteAt: now, window: idleStopWindow}
}

// check 记录本轮情况，必要时返回 prevent=true 要求收场。
//
// messages 参数不使用——判据只看写回增量，不看模型说了什么。看文本会有两个
// 坏处：模型可以自己宣称「我已经探完了」来骗过判据；而一个正在认真做
// 多步利用链的 worker 会说很多话，被误判成「还在产出」。
//
// 「一轮」的口径：**一次工具执行**（PreToolUse 放行 → PostToolUse 记一次）。
// 早期版本把「一轮」定义成 assistant 回合，但 SDK 只在「该轮没调工具」时才
// 调 Stop，那个口径在持续干活的 worker 上永远推进不了（见文件头注释）。
func (s *idleStopper) check() (prevent bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先看有没有新写回——有就清零（这一轮是产出的）。
	if s.refreshLocked() {
		return false, ""
	}
	// 这一轮过去了，计数 +1。
	s.rounds++
	// 起跑宽限期内不收场。
	if time.Since(s.start) < idleStopMinElapsed {
		return false, ""
	}
	if !s.trippedLocked() {
		return false, ""
	}
	// 已经达过阈值：持续返回 prevent。
	if s.stopped {
		return true, s.reason
	}
	s.stopped = true
	s.reason = fmt.Sprintf("连续%d轮无写回（本轮写回 %d 条，产出率已归零）", s.rounds, s.totalLocked())
	return true, s.reason
}

// peek 判断「当前是否已经空转到该收场的程度」，**不推进计数**。
//
// 为什么要单独的 peek：check() 的语义是「调用即推进一轮」（Stop 路径靠这个
// 推进）。而 PreToolUse 在一次工具执行前也会被调用——如果它也用 check()，
// 同一轮就会被推进两次（PreToolUse 一次、随后的 Stop 又一次），阈值从
// 「连续 3 轮」缩成「连续 1.5 轮」，太激进，会误杀正在准备写回的 worker。
func (s *idleStopper) peek() (prevent bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshLocked() {
		return false, ""
	}
	if s.stopped {
		return true, s.reason
	}
	if time.Since(s.start) < idleStopMinElapsed {
		return false, ""
	}
	if !s.trippedLocked() {
		return false, ""
	}
	return true, fmt.Sprintf("连续%d轮无写回（本轮写回 %d 条，产出率已归零）", s.rounds, s.totalLocked())
}

// trippedLocked 判断是否达到空转判据。调用方必须持有 s.mu。
//
// 判据是**双条件**（2026-11-05 调整）：
//   - 轮数下限 idleStopRounds（连续多少次工具执行没写回）
//   - 且满足其一：距上次写回超过 window，**或** 轮数达到 idleStopHardRounds
//
// window<=0 时退化为纯轮数判据（单测用它验证轮数逻辑，不受墙上时间影响）。
func (s *idleStopper) trippedLocked() bool {
	if s.rounds >= idleStopHardRounds {
		return true
	}
	if s.rounds < idleStopRounds {
		return false
	}
	if s.window <= 0 {
		return true
	}
	return time.Since(s.lastWriteAt) >= s.window
}

// advance 记一轮过去（一次工具执行）。
//
// 计数由 PostToolUse 推进——它是**每轮都调工具的 worker** 唯一会走的路径。
// Stop 路径另有一次推进（见 check），两者互斥：一条回合要么调了工具
// （PostToolUse 推进、Stop 不被调），要么没调（Stop 推进），不会重复计数。
func (s *idleStopper) advance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshLocked() {
		// 这一轮有产出 → refreshLocked 已清零，不再 +1。
		return
	}
	s.rounds++
}

// refreshLocked 在有新增写回时清零计数，返回「本轮是否有产出」。
// 调用方必须持有 s.mu。
func (s *idleStopper) refreshLocked() bool {
	total := s.totalLocked()
	if total > s.lastWrites {
		s.lastWrites = total
		s.rounds = 0
		s.stopped = false
		s.nudged = false
		s.lastWriteAt = time.Now()
		return true
	}
	return false
}

// totalLocked 读当前累计写回数。调用方必须持有 s.mu。
func (s *idleStopper) totalLocked() int {
	if s.writes == nil {
		return 0
	}
	return s.writes().Total()
}


// idleStopHooks 把 idleStopper 挂在 harness 的 hook 链上。
//
// 它是**旁路观察 + 收场请求**的组合：
//   - PreToolUse/PostToolUse：原样转发给 inner（日志层不拦截）。
//   - Stop：在 inner 的 Stop 之后检查；inner 决定要停就停，inner 没意见而
//     产出率归零，就要求收场。
//
// 顺序：先转发 inner 再判断。inner 是拦截管控（guard），它说停就必须停；
// 我们只在 inner 放行、且本轮确实没产出时才追加「收场」的要求。
//
// ## 为什么用 blocking 而不是直接 prevent
//
// harness 的 Stop hook 有两种返回：
//   - prevent=true → 立刻终止 run，模型**没有机会写回**。
//   - blocking=[]string → SDK 把这些字符串作为 user 消息注入，模型**再跑一轮**。
//
// 这里要的是后者：worker 跑到一半被判空转时，它可能正拿着一堆「探到了但还没
// 写回」的东西。直接 prevent 会把这些全丢掉——那才是真正的浪费。所以流程是：
//
//	第 1 次触发 → blocking：告诉模型「这个方向探不到新东西了，把已确认的写回，
//	                 然后用一句话总结收手」
//	第 2 次触发 → prevent：模型已经给过总结、还不肯停，就真的收场
//
// stopHookActive 机制保证不会死循环：SDK 注入 blocking 后会把 stopHookActive
// 置位，直到发生一次真正的工具回合才复位。
type idleStopHooks struct {
	inner harness.HookRunner
	stop  *idleStopper
	// onStop 被调用一次（带收场原因），用于落日志/落库。
	onStop func(reason string)
	// nudged 记录是否已经给过 blocking 提示（给过之后才允许 prevent）。
	nudged bool
	// mu 保护 nudged（Stop 可能被并发调用）。
	mu sync.Mutex
}

// PreToolUse 是空转判据的**主挂点**：SDK 每次工具执行前都调它
// （harness/tools.go:78），而 Stop 只在「该轮没调工具」时才调。
//
// 达到阈值时：阻止本次工具调用，并把「请把已确认的结果写回、然后收手」
// 作为工具结果回传给模型（block=true + message，与 steer_work 纠偏同一个
// 模式）。模型收到后可以用 record_fact / report_finding / insert_assets
// 把成果写回——那三样**不经过**这个钩子（它们是普通工具调用，但写回本身
// 会让计数归零）。
//
// 第一次拦是提示，模型若仍不停（继续调工具且仍零写回），第二次才真收场。
func (h *idleStopHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	// 写回类工具直接放行：worker 正要把成果落库时拦它 = 把成果丢掉。
	if idleStopWriteTools[name] {
		if h.inner != nil {
			return h.inner.PreToolUse(ctx, name, input)
		}
		return false, "", nil
	}
	// inner（guard 管控链）先走——空转判据不能绕过拦截规则。
	if h.inner != nil {
		if block, msg, updated := h.inner.PreToolUse(ctx, name, input); block {
			return block, msg, updated
		}
	}
	prevent, reason := h.stop.peek()
	if !prevent {
		return false, "", nil
	}
	h.mu.Lock()
	alreadyNudged := h.nudged
	h.nudged = true
	h.mu.Unlock()
	if !alreadyNudged {
		// 第一次：拦住这次工具调用，提示模型写回并收手（它还有机会把成果落库）。
		return true, idleStopMessage, nil
	}
	// 第二次：提示过还不停，真的收场。
	if h.onStop != nil {
		h.onStop(reason)
	}
	return true, idleStopMessage + "（已多次提示未收场，本轮就此结束）", nil
}

// PostToolUse 推进「一轮」的计数：一次工具执行 = 一轮。
//
// 为什么放在这里而不是 PreToolUse：PreToolUse 放行后工具**可能失败**（命令
// 报错、网络不通），那仍然是一次「这一轮没产出」——应该计入。放在 PostToolUse
// 能把成功和失败的工具调用都算上。
func (h *idleStopHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
	// 写回类工具不推进计数（它是结束动作，见 idleStopWriteTools 的说明）。
	if idleStopWriteTools[name] {
		return
	}
	// 一次工具执行 = 一轮，推进计数。
	//
	// 为什么由这里推进：PreToolUse 只做判断（peek），Stop 只在「该轮没调工具」
	// 时才被调用。持续干活的 worker 走的正是「每轮都调工具」这条路——它的
	// 轮次计数只能由 PostToolUse 推进，否则计数永远停在 0，空转判据不成立。
	h.stop.advance()
}

func (h *idleStopHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		prevent, blocking, msg := h.inner.Stop(ctx, messages)
		if prevent {
			return prevent, blocking, msg
		}
	}
	prevent, reason := h.stop.check()
	if !prevent {
		return false, nil, ""
	}
	h.mu.Lock()
	alreadyNudged := h.nudged
	h.nudged = true
	h.mu.Unlock()
	if !alreadyNudged {
		// 第一次触发：给模型一次把已确认结果写回的机会。
		return false, []string{idleStopMessage}, ""
	}
	// 第二次触发：模型已经收到提示还不停，真的收场。
	if h.onStop != nil {
		h.onStop(reason)
	}
	return true, nil, reason
}

// wrapIdleStop 把 idleStopper 套在已有 hook 链外层。
func wrapIdleStop(inner harness.HookRunner, writes func() WriteCounts, onStop func(string)) *idleStopHooks {
	return &idleStopHooks{inner: inner, stop: newIdleStopper(writes), onStop: onStop}
}

// idleStopWriteTools 是「写回类」工具：它们是**结束动作**而不是探测动作。
//
// 为什么它们不参与空转判据：
//   - 绝不能被拦。worker 攒了一堆成果正要 record_fact 写回，这时拦住它 =
//     把成果全丢掉——那比空转更糟。
//   - 不推进计数。写回会让 writes 增长，计数自然被 refreshLocked 清零；
//     再额外推进一次等于把「有产出」的一轮算成两轮。
var idleStopWriteTools = map[string]bool{
	"record_fact":     true,
	"insert_assets":   true,
	"report_finding":  true,
}

// idleStopMessage 是拦住工具调用时给模型的说明。
//
// 2026-11-05 调整措辞：原文是「请立刻停止继续探测……结束本轮」，实测模型会
// 直接放弃正在跑的利用链（任务 333 一夜 218 次触发）。现在改成
// 「先写回、再判断是否继续」——把「收场」从一个命令降级成一个选项，
// 避免把「暂时没写回」误当成「这个方向没价值」。
//
// 说清「为什么拦」很重要：模型看到「预算耗尽被终止」会以为是被惩罚，于是
// 倾向于把还没验证的东西也写成结论；看到「这段时间没有写回，请先落库」它会
// 正确处理。
const idleStopMessage = "这段时间没有任何新发现被写回。请先把**已经确认**的结果落库（资产用 insert_assets、结论用 record_fact、确认漏洞用 report_finding），再判断是否继续：确有明确的下一步，写回后接着做；确实探到底了，就用一句话说明你探到了什么、卡在哪里，然后结束本条意图。不要为了「有产出」而把没验证的猜测写成事实。"

// logIdleStop 记一条收场日志（统一格式，便于事后统计）。
func logIdleStop(worker string, taskID int64, intentID int64, reason string) {
	log.Printf("[worker %s] task %d intent #%d 无增量自动收场: %s", worker, taskID, intentID, reason)
}

// summarizeWriteDelta 描述一轮的写回增量（调试/日志用）。
func summarizeWriteDelta(cur, prev WriteCounts) string {
	return fmt.Sprintf("事实+%d 资产+%d 漏洞+%d",
		cur.Facts-prev.Facts, cur.Assets-prev.Assets, cur.Findings-prev.Findings)
}

// idleStopStateText 是给 planner 看的一句话说明（写进意图的停止原因）。
//
// planner 靠它区分两种 exhausted：
//   - 「被墙钟掐断」（还有明确的下一步，只是没时间）
//   - 「探到边界」（这个方向本身没东西了）
// 这两种在 planner 的决策里完全相反，混在一起就会导致「一直续派同一方向」。
func idleStopStateText(reason string) string {
	return strings.TrimSpace(reason)
}
