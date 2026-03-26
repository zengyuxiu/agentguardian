# AgentGuardian 配置持久化与规则管理设计稿

## 1. 背景

当前 AgentGuardian 的配置模型仍然是“进程启动时通过 flags 解析一组参数，然后直接写入 eBPF maps”。

现状特征：

- 用户态只有一个扁平 `Config`
- `cmd/agentguardian` 启动后立即 `Apply()` 下发策略
- `rewrite-exe` / `hide-exe` 通过轮询 `/proc` 编译成 PID 策略
- eBPF 侧只支持按 `pid` 或 `comm` 返回一条生效 policy

这套模型适合演示和单次运行，不适合长期管理：

- 没有规则 ID，无法稳定地 `list/delete/update`
- 没有持久化存储，重启后规则丢失
- 没有优先级和冲突处理，多条规则无法稳定合并
- 没有 `runtime` / `permanent` 区分
- 没有原子 apply，未来扩展成多规则后容易出现半更新状态

本设计稿的目标，是把 AgentGuardian 提升为“类似 nftables / ufw 的本地规则管理工具”，但保持内核态逻辑简单，避免把复杂规则链直接塞进 eBPF。

## 2. 设计目标

### 2.1 目标

- 支持规则持久化，重启后可恢复
- 支持多条规则管理：`add/list/get/delete/enable/disable/apply`
- 支持明确的优先级与冲突决策
- 支持声明式配置文件，便于审计和版本管理
- 支持运行态与永久态分离
- 保持 eBPF 侧 lookup 简单、高性能、可验证
- 为后续扩展更多 action 和 selector 预留空间

### 2.2 非目标

- 当前阶段不引入分布式配置中心
- 当前阶段不实现复杂的内核态规则链遍历
- 当前阶段不支持多机集群同步
- 当前阶段不引入 SQL 作为默认存储

## 3. 现有实现约束

### 3.1 用户态约束

当前 `config.Config` 是单实例扁平结构，只能表达一个目标路径下的一组 selector 和 action 参数组合。

影响：

- 无法表达真正的“规则集”
- 无法给每条规则分配 ID、注释、启用状态、优先级
- 无法做稳定的增删改查

### 3.2 内核态约束

当前 eBPF 的核心生效路径是：

1. 先查 `policy_map[pid]`
2. 查不到再查 `comm_policy_map[comm]`
3. 返回单条 policy

这意味着内核侧是“最终态查表”，不是“规则链求值”。

这是限制，也是优势：

- 限制：不能直接表达多条规则求值过程
- 优势：运行开销低，逻辑清晰，验证器压力小

因此推荐的方向不是把规则链搬进 BPF，而是在用户态做“规则编译器”，把高层规则集编译成最终生效表。

## 4. 总体方案

采用三层模型：

1. `Persistent Ruleset`
   - 永久存储的声明式规则
   - 放在磁盘，可审计、可编辑、可版本管理
2. `Compiled Runtime State`
   - 规则编译结果
   - 表示当前应写入哪些 eBPF maps
3. `eBPF Enforcement`
   - 内核态最终执行
   - 只负责按 key 查找最终 policy，不负责复杂规则计算

整体上更接近 `nftables`：

- 高层规则以声明式形式保存
- 用户态控制面做校验、排序、冲突消解、编译
- 编译结果原子写入运行态

## 5. 组件划分

建议新增两个组件：

### 5.1 `agentguardd`

职责：

- 加载 eBPF runtime
- 读取永久规则
- 监听配置变更或接收 CLI 请求
- 将规则集编译为运行态视图
- 负责原子 apply 到 eBPF maps
- 提供状态查询接口

建议运行方式：

- 由 systemd 启动
- 开机恢复 `permanent` 配置
- 通过 Unix socket 提供本地管理接口

### 5.2 `agctl`

职责：

- 用户交互入口
- 管理 `rules.d` 中的规则文件
- 向 `agentguardd` 发送 `reload/apply/status` 请求
- 输出人类可读的状态、diff、验证结果

示例命令：

```bash
agctl rule add --file ./rule.yaml
agctl rule list
agctl rule get rewrite-cat-token
agctl rule disable rewrite-cat-token
agctl rule delete rewrite-cat-token
agctl apply
agctl diff
agctl status
agctl save
agctl reload
```

## 6. 持久化方案

### 6.1 推荐方案

默认使用目录式声明式存储：

```text
/etc/agentguardian/
  agentguardian.yaml
  rules.d/
    010-hide-claude-passwd.yaml
    100-rewrite-cat-token.yaml
  runtime.json
```

其中：

- `agentguardian.yaml` 保存全局配置
- `rules.d/*.yaml` 每个文件一条或一组规则
- `runtime.json` 记录最近一次成功 apply 的摘要、generation、时间戳和诊断信息

推荐理由：

- 人可读
- 易于 git 管理
- 易于排障
- 易于做增量迁移
- 不需要先引入数据库

### 6.2 为什么不默认使用 SQLite

SQLite 适合以下场景：

- 多客户端并发修改
- 强事务需求
- 复杂查询
- 审计历史、回滚记录很多

但对 AgentGuardian 第一阶段而言，它有两个明显问题：

- 人工排障和手工维护不如 YAML 直接
- 对当前本地单机场景是过度设计

结论：

- V1 默认用 `rules.d/*.yaml`
- 只有在后续引入多写者、审计历史和复杂检索时，再考虑 SQLite

## 7. 规则模型

### 7.1 规则对象

```yaml
id: hide-claude-passwd
enabled: true
priority: 100
match:
  path: /etc/passwd
  exe: /opt/claude-code/bin/claude
action:
  type: hide
comment: deny claude reading passwd
```

```yaml
id: rewrite-cat-token
enabled: true
priority: 200
match:
  path: /tmp/ag-test.txt
  comm: cat
action:
  type: rewrite
  find: secret
  replace: public
comment: return honey content to cat
```

### 7.2 Go 结构建议

```go
type Ruleset struct {
    Version int           `yaml:"version"`
    Rules   []Rule        `yaml:"rules"`
}

type Rule struct {
    ID       string       `yaml:"id"`
    Enabled  bool         `yaml:"enabled"`
    Priority int          `yaml:"priority"`
    Match    MatchSpec    `yaml:"match"`
    Action   ActionSpec   `yaml:"action"`
    Comment  string       `yaml:"comment,omitempty"`
}

type MatchSpec struct {
    Path string   `yaml:"path"`
    PID  *uint32  `yaml:"pid,omitempty"`
    Comm string   `yaml:"comm,omitempty"`
    Exe  string   `yaml:"exe,omitempty"`
}

type ActionSpec struct {
    Type    string `yaml:"type"`
    Find    string `yaml:"find,omitempty"`
    Replace string `yaml:"replace,omitempty"`
}
```

### 7.3 字段约束

- `id` 必须唯一
- `enabled` 缺省为 `true`
- `priority` 越小优先级越高
- `match.path` 必填
- `match.pid` / `match.comm` / `match.exe` 至少填一个
- `action.type` 当前只允许 `hide` 或 `rewrite`
- `rewrite` 必须同时提供 `find` 和 `replace`
- `find` 与 `replace` 长度必须一致

## 8. 规则匹配与冲突决策

### 8.1 推荐优先级

当多个规则可能命中同一主体时，按以下顺序决定最终策略：

1. selector 具体度
   - `pid` 高于 `exe`
   - `exe` 高于 `comm`
2. `priority`
   - 数字越小优先级越高
3. action 冲突
   - `hide` 高于 `rewrite`
4. 最后按 `id` 字典序稳定排序

### 8.2 为什么要先用户态冲突决策

原因很直接：

- 当前内核态只支持单条 policy 查找
- 在 eBPF 中维护规则链会显著增加复杂度
- `/proc` 扫描出的 `exe -> pid` 映射天然属于用户态编译行为

因此控制面应把多条规则压平为“最终生效 policy”。

## 9. 编译模型

### 9.1 输入

- 永久规则集
- 当前运行时进程视图
- 全局默认行为

### 9.2 输出

编译后的运行态：

- `pid -> effective policy`
- `comm -> effective policy`
- 元数据：
  - generation
  - 来源规则 ID
  - apply 时间
  - 编译告警

### 9.3 编译步骤

1. 加载所有规则文件
2. 做 schema 校验和语义校验
3. 过滤 `enabled=false`
4. 统一 canonicalize 路径
5. 将规则按优先级排序
6. 构建三个中间集合
   - 直接 PID 规则
   - Comm 规则
   - Exe 规则
7. 扫描 `/proc`，将 `exe` 规则展开为 PID 规则
8. 按冲突决策生成最终 `pid/comm` 生效表
9. 生成 apply plan

### 9.4 为什么不保留 `exe_policy_map`

V1 不建议引入 `exe_policy_map`，原因：

- 当前内核态没有直接稳定的“可执行文件路径查找”链路
- 继续保留“用户态展开 exe 到 pid”的方式更符合现状
- 这样能最小化 BPF 改动范围

后续如果要降低 `/proc` 轮询带来的竞态，再考虑：

- `sched_process_exec` 事件驱动同步
- task inode / cgroup / mount namespace 等更稳定 selector

## 10. Apply 事务模型

### 10.1 核心要求

- apply 要么整体成功，要么保留旧状态
- 避免清空旧 map 后写新 map 过程中出现短暂空窗
- 能看到当前 generation 和最近一次失败原因

### 10.2 推荐实现

V1 采用“用户态事务 + 双缓冲思想”：

1. 读取当前运行态摘要
2. 在内存中构建完整的目标状态
3. 先写入 staging maps
4. 校验 staging maps 内容完整
5. 切换 active generation
6. 清理旧 generation

如果现阶段不想改 BPF map 结构，可以先做简化版：

1. 在用户态算出 diff
2. 先写新增和修改
3. 再删多余项
4. 整个 apply 带 generation 标识并写入 `runtime.json`

更长期的标准做法：

- 引入 map-in-map 或 generation map
- BPF 运行时只读取当前 active generation 指向的那组 maps

### 10.3 推荐的运行态元数据

```json
{
  "generation": 12,
  "applied_at": "2026-03-18T16:30:00Z",
  "rule_count": 7,
  "pid_policy_count": 21,
  "comm_policy_count": 3,
  "warnings": [
    "rule rewrite-short-lived-node may miss short-lived processes because exe expansion uses /proc polling"
  ]
}
```

## 11. Runtime / Permanent 语义

借鉴 firewalld，引入两套语义：

- `runtime`
  - 当前已下发到 eBPF maps 的状态
  - 可临时修改
  - 守护进程退出后丢失
- `permanent`
  - 磁盘上的规则文件
  - 重启后恢复来源

建议命令语义：

```bash
agctl rule add --file ./x.yaml --permanent
agctl rule add --file ./x.yaml --runtime
agctl apply
agctl save
```

说明：

- `--runtime` 只改内存规则集
- `--permanent` 修改磁盘规则
- `save` 将 runtime 覆盖写回 permanent

如果第一阶段想降复杂度，也可以先只做 `permanent + apply`，不立即支持 runtime/permanent 双态。

## 12. CLI 设计

### 12.1 命令集合

```bash
agctl rule add --file rule.yaml
agctl rule list
agctl rule get <id>
agctl rule delete <id>
agctl rule enable <id>
agctl rule disable <id>
agctl validate
agctl diff
agctl apply
agctl status
agctl reload
agctl save
```

### 12.2 输出要求

- `rule list` 显示 `id/enabled/priority/match/action/source`
- `diff` 显示本次编译将新增、覆盖、删除哪些运行态项
- `status` 显示当前 generation、BPF attach 状态、最近 apply 时间、错误信息
- `validate` 不写入任何 map，只报告问题

## 13. 目录结构建议

建议新增：

```text
cmd/
  agentguardd/
  agctl/
internal/
  rules/
    model.go
    validate.go
    compiler.go
    loader.go
    store.go
    runtime.go
doc/
  config-persistence-design.md
```

模块职责：

- `model.go`: 规则结构定义
- `validate.go`: schema 和语义校验
- `loader.go`: 读取 `rules.d`
- `compiler.go`: 规则集编译成运行态视图
- `store.go`: 永久态文件读写
- `runtime.go`: apply、status、generation、diff

## 14. 迁移路径

### Phase 1

- 保留现有 `cmd/agentguardian`
- 新增 `internal/rules`
- 支持读取单个 YAML ruleset
- 用户态编译成当前已有的 `policy_map` / `comm_policy_map`
- 不改 eBPF 生效模型

收益：

- 很快获得持久化、规则 ID、list/diff/apply 能力
- 对现有 BPF 改动最小

### Phase 2

- 拆出 `agentguardd` 与 `agctl`
- 引入 `rules.d` 目录和 Unix socket
- 支持 `validate/status/reload`
- 明确 `runtime` 与 `permanent`

### Phase 3

- 优化 `exe` 规则同步模型
- 从 `/proc` polling 迁移到事件驱动
- 视需要引入 generation 双缓冲 maps

## 15. 风险与注意事项

### 15.1 `exe` 规则竞态

只要 V1 还依赖 `/proc` 扫描，把 `exe` 展开成 PID，短生命周期进程竞态就依然存在。

处理方式：

- 在设计上显式承认这个限制
- 编译诊断中输出 warning
- 后续单独优化

### 15.2 冲突透明性

规则编译后，用户必须能知道：

- 哪条规则赢了
- 哪条规则被覆盖了
- 为什么被覆盖

因此 `diff` 和 `status` 里应保留“源规则 ID -> 生效项”的映射信息。

### 15.3 回滚

如果 apply 失败，必须保留上一次成功 generation 的状态摘要。

V1 即便没有真正 map 双缓冲，也至少要做到：

- apply 前保存当前摘要
- 失败时记录失败原因
- 不清空现有规则直到新规则写入完成

## 16. 推荐结论

推荐采用以下路线：

1. 以 `rules.d/*.yaml` 作为永久规则存储
2. 在用户态增加规则模型、校验器和编译器
3. 继续让 eBPF 保持“最终态查表”，不做复杂规则链
4. 用 `agentguardd + agctl` 提供持久化管理能力
5. 第一阶段不引入 SQLite，先用声明式文件和原子 apply

这是对当前代码侵入最小、工程上最稳、也最接近成熟防火墙管理模型的一条路线。

## 17. 后续落地建议

建议按以下顺序实施：

1. 新增 `internal/rules` 包，完成模型、校验和 YAML 读取
2. 把现有 `config.Config` 的 flag 逻辑降级为兼容入口
3. 新增 `compiler`，把规则集编译到当前 `policy_map` / `comm_policy_map`
4. 新增 `agctl validate/diff/apply`
5. 最后再拆 `agentguardd`

这样可以先获得规则持久化和管理能力，再逐步把运行入口从单进程 CLI 迁移到守护进程模式。
