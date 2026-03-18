# AgentGuardian Runtime/Permanent 进度与后续规划

## 当前进度

### 已完成

- 保留原有 `cmd/agentguardian` flags 入口
- 新增 `-rules`，支持从单个 YAML 文件或目录读取 `Ruleset`
- 新增 `internal/rules`
  - 规则模型
  - YAML 读取
  - 语义校验
  - ruleset -> `policy_map` / `comm_policy_map` 编译
- 新增 `cmd/agentguardd`
  - 加载 eBPF runtime
  - 以 `config-dir/rules.d` 作为 permanent 规则目录
  - 启动 Unix socket 控制 API
  - 启动时将 permanent reload 到 runtime
- 新增 `cmd/agctl`
  - `status`
  - `validate`
  - `reload`
- 新增 `internal/control`
  - `Service`
  - Unix socket HTTP/JSON server/client
  - runtime/permanent 状态建模

### 当前语义

- `permanent`
  - 磁盘上的 `rules.d`
  - 通过 `status` / `validate permanent` 查看
- `runtime`
  - daemon 内存中当前已编译并下发到 BPF maps 的规则快照
  - 通过 `status` / `validate runtime` 查看
- `reload`
  - 重新读取 permanent
  - 编译
  - 覆盖当前 runtime

### 当前边界

- 还没有 `save`
- 还没有 `apply --runtime`
- 还没有 runtime override 持久化
- 还没有 rules.d 文件热重载
- 还没有保留“原始多文件结构和注释”的回写能力

## 当前架构

### 控制面

- `agentguardd`
  - eBPF runtime owner
  - control API server
  - runtime state owner
- `agctl`
  - 调用 daemon 的 Unix socket API

### 数据流

1. 从 `rules.d` 读取 permanent ruleset
2. 编译为 `pid` / `comm` 最终态
3. 写入 `policy_map` / `comm_policy_map`
4. 将编译结果记录为 runtime state

## 为什么现在还不算完整的 runtime/permanent 管理

因为目前 runtime 仍然是 permanent 的派生结果，而不是一套可独立编辑、可保存、可回滚的对象。

换句话说：

- 现在可以 `reload`
- 现在可以 `validate`
- 现在可以 `status`
- 但还不能：
  - 只在 runtime 新增一条规则
  - 只在 runtime 临时 disable 一条规则
  - 将 runtime 写回 permanent

## 建议的后续模型

建议把规则状态明确拆成三层：

1. `permanentRuleset`
   - 来自 `rules.d`
2. `runtimeOverride`
   - daemon 内存中的临时规则或规则替换
3. `effectiveRuntime`
   - `permanentRuleset + runtimeOverride`
   - 编译后实际写入 BPF maps

这样命令语义才稳定：

- `reload`
  - 丢弃 runtime override
  - 从 permanent 重建 effective runtime
- `apply --runtime`
  - 修改 runtime override
  - 重新生成 effective runtime
- `save`
  - 将当前 effective runtime 导出回 permanent

## 后续开发顺序

### Phase 1: 完整 runtime apply/save 闭环

新增：

- `POST /v1/runtime/apply`
- `POST /v1/runtime/save`
- `GET /v1/runtime/export`
- `agctl apply --runtime --file runtime.yaml`
- `agctl save`

建议实现方式：

- `apply --runtime`
  - 先只支持“完整 ruleset 替换”
  - 不先做细粒度 patch
- `save`
  - 先输出一个规范化 ruleset 文件
  - 不承诺保留原始文件拆分和注释

这样能最快形成闭环。

### Phase 2: 细粒度 runtime override

新增：

- `agctl rule add --runtime`
- `agctl rule delete --runtime`
- `agctl rule enable --runtime`
- `agctl rule disable --runtime`

这一阶段才引入“规则级 patch”。

### Phase 3: 文件热重载与审计

新增：

- rules.d 文件变更监听
- reload 事件日志
- generation 变更历史
- runtime/permanent diff

## 风险点

### 1. `save` 语义

真正困难的不在写盘，而在“如何写回”。

如果 permanent 允许用户自行维护多个 YAML 文件、文件名顺序和注释，那么 `save` 的行为必须明确：

- 是覆盖整个 rules.d
- 还是只写一个 generated 文件
- 是否尝试保留原文件结构

建议 V1 先采用：

- `save` 导出单个规范化文件
- 或导出到独立目标目录

不要在第一版尝试保留原始格式。

### 2. runtime override 的冲突决策

当 permanent 和 runtime 同时存在时，必须固定规则：

- runtime override 优先于 permanent
- 同级仍沿用：
  - `pid > exe > comm`
  - 更小 `priority`
  - `hide > rewrite`

### 3. `exe` 规则同步

目前 `exe` 规则仍依赖用户态扫描 `/proc` 展开为 PID。

这意味着：

- runtime generation 可能因进程变化而变化
- 短生命周期进程仍有竞态

后续如要优化，应转向事件驱动同步，而不是持续轮询。

## 建议的近期目标

建议下一阶段只做下面三件事：

1. `agctl apply --runtime --file ...`
2. `agctl save`
3. `status` 中加入 runtime/permanent diff 摘要

这样就能把当前“只会 reload 的控制面”推进为真正具备双态管理能力的控制面。
