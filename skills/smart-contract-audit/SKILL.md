---
name: smart-contract-audit
description: 目标含 Solidity/智能合约、Web3 DApp、链上资产相关系统时调用——常见合约漏洞（重入/预言机/权限/签名）、审计工具(slither/mythril)、链上验证与影响判定。
tags:
  cwe: [CWE-682, CWE-367, CWE-284, CWE-347]
  attack: [T1195]
  class: [blockchain, solidity, smart-contract, web3]
---

# 智能合约审计速查

## 高频漏洞

| 漏洞 | 特征 | 验证 |
|---|---|---|
| 重入 | 先转账后改状态；外部调用未加锁 | 构造攻击合约，本地 fork 主网复现 |
| 权限缺失 | `onlyOwner` 遗漏、`initialize` 可重复调用 | 直接调受限函数看是否成功 |
| 预言机操纵 | 现货价格做抵押定价 | 闪电贷操纵价格路径推演/本地复现 |
| 签名重放 | 无 nonce/链 ID/合约地址 | 同一签名用两次 |
| 越权转账 | `transferFrom` 缺 allowance 校验 | 本地复现 |
| 整数问题 | 未用 SafeMath（旧 Solidity）、精度损失 | 边界值测试 |
| 随机数可预测 | `block.timestamp/blockhash` 做随机 | 本地复现 |
| delegatecall | 代理模式存储布局冲突/任意地址 | 存储槽对比 |

## 工具链

- `slither .`（静态快速）：reentrancy-eth、arbitrary-send、controlled-delegatecall；
- `mythril analyze`（符号执行，慢）；
- `forge test`（本地 fork 复现，最可信）；
- 反编译链上合约：etherscan 源码 → 无源码时 `heimdall`/`panoramix`。

## 链上验证（只读）

- 读合约：`cast call <addr> "balanceOf(address)(uint256)" <user>`；
- 事件与交易：`cast logs`/浏览器；
- 未授权读链上数据不算漏洞（链上本就公开）；关注 **合约业务逻辑可被任意人滥用**。

## DApp / Web3 前端

- 私钥/助记词硬编码（前端 bundle）——立即落 fact；
- RPC 端点未授权/可任意 `eth_sendRawTransaction`；
- 签名钓鱼（`eth_sign` 任意消息）、`permit` 授权滥用；
- 前端调用的合约地址与审计对象不一致（代理升级）。

## 边界

- 只在测试网或本地 fork 验证；主网只做只读调用；
- 不发送任何会转移资产的交易；
- 复现脚本与交易哈希写入证据。
