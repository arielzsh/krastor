# Krastor — Coverage-Guided Fuzzer for Solana Programs

> renascence of Ackee Blockchain's Trident · arielzsh · Bubblegum Labs · 2026-05-23

## 概念模型

Krastor 是一个 Solana 程序漏洞挖掘工具，融合三种能力：

```
覆盖率引导        自动序列编排        Solana账户感知
  (白盒)             (跨指令)            (定向攻击)
    │                   │                    │
    └───────────┬───────┴────────────────────┘
                │
          Krastor Fuzzer
                │
    ┌───────────┼────────────┐
    │           │            │
  LiteSVM    invariants    account
  runtime    runtime        mutators
```

## 核心架构

```
krastor/
├── crates/
│   ├── fuzz-core/        # 核心引擎：随机序列 + 账户突变 + LiteSVM + 不变量
│   ├── idl-parser/       # Anchor IDL 解析 + harness 代码生成
│   ├── instrumentor/     # SBF 字节码静态插桩 + 覆盖位图（可选模块）
│   ├── cli/              # cargo-krastor 命令行
│   └── report/           # 覆盖率报告 + crash JSON 持久化
└── examples/vulnerable/  # 含已知漏洞的测试合约
```

## 与 proptest + LiteSVM 的本质区别

| | proptest | Krastor |
|---|---|---|
| 探索策略 | 均匀随机采样 | **覆盖率引导定向收敛** |
| 序列生成 | 手动编写 action 枚举 | **IDL 自动推导所有指令** |
| 账户突变 | 通用字节翻转 | **Solana 模型感知定向攻击** |
| 配置成本 | 2-3 天手工编码 | **30 分钟 IDL 驱动自动生成** |
| 覆盖率反馈 | 无 | **白盒 + 黑盒双重检测** |

## 三个不可替代的优势

1. **覆盖率引导的定向探索** — 不是随机撞大运，而是系统性逼近未覆盖分支
2. **跨指令序列自动编排** — 自动尝试任意长度、任意顺序的指令组合（闪电贷攻击模式）
3. **Solana 账户模型原生感知** — owner 替换、lamports 归零、data 清空等定向攻击

## 三个关键劣势与对策

| 劣势 | 对策 |
|------|------|
| SBF 插桩层脆弱 | 插桩与引擎解耦，降级为可选模块 |
| 外部依赖链长 | 只用 LiteSVM（嵌入式运行时，零外部进程） |
| 缺少自动化精简 | Crash 序列二分 + 贪心删除 Shrinking |

## 快速开始

```bash
cargo install cargo-krastor
krastor init                    # 读取 Anchor IDL，生成 harness
krastor fuzz run --iterations 100000  # 开始 fuzz
krastor fuzz repro crash.json   # 复现 crash
krastor fuzz coverage           # 查看覆盖率报告
```

## 依赖

- Rust 1.75+
- Zig 0.17 (instrumentor 需要)
- LiteSVM (嵌入式 Solana 运行时)
- Anchor IDL JSON (合约输入)