# AgentGuardian

`AgentGuardian` 是一个基于 eBPF 的文件访问防护工具。

它当前提供两类能力：

- `hide`: 对指定进程隐藏目标文件，效果类似返回 `ENOENT`
- `rewrite`: 在指定进程读取目标文件时，按固定字符串规则改写读取结果

项目使用 Go + `cilium/ebpf`，BPF 代码位于内核态，控制逻辑位于用户态。

## 适用场景

- 阻止指定 AI Agent 或工具读取敏感文件
- 为特定进程返回蜜罐内容或脱敏内容
- 验证“按进程而非线程”跟踪文件描述符的 eBPF 行为

## 当前能力范围

- 拦截 `openat/openat2/read/close`
- 支持按 `pid`、进程名 `comm`、可执行文件路径 `exe` 下发策略
- `rewrite` 按进程粒度跟踪 `fd`
- `hide` 依赖 `lsm/file_open`

限制：

- `rewrite` 目前只处理 `read(2)` 路径
- `rewrite` 只支持等长替换：`-find` 与 `-replace` 长度必须一致
- `hide-exe` / `rewrite-exe` 通过扫描 `/proc` 同步 PID，短生命周期进程可能有竞态

## 环境要求

- Linux
- root 权限，或无密码 `sudo`
- 建议内核 `>= 5.10`
- 系统提供 `/sys/kernel/btf/vmlinux`
- 已安装 `clang`、Go、构建 eBPF 所需基础工具

## 构建

```bash
make
```

产物：

- 可执行文件：
  - `bin/agentguardian`
  - `bin/agentguardd`
  - `bin/agctl`

常用命令：

```bash
make test
make integration-test
```

## 快速开始

### 1. 按进程隐藏文件

```bash
sudo ./bin/agentguardian \
  -hide-exe /opt/claude-code/bin/claude \
  -path /tmp/replacetest
```

如果当前内核不支持 `lsm/file_open`，程序会启动，但日志会提示 `hide action disabled`。

### 2. 按进程改写读取内容

```bash
printf 'secret-token\n' > /tmp/ag-test.txt

sudo ./bin/agentguardian \
  -path /tmp/ag-test.txt \
  -rewrite-exe /usr/bin/cat \
  -find secret \
  -replace public
```

然后执行：

```bash
cat /tmp/ag-test.txt
```

预期输出：

```text
public-token
```

### 3. 默认改写自身进程

如果只传 `-find/-replace`，没有显式指定任何 `rewrite-*` 目标，程序会默认对自身 PID 下发 rewrite 策略。

### 4. 从 YAML 规则集启动

单文件 ruleset：

```bash
sudo ./bin/agentguardian -rules ./rules.yaml
```

目录式 ruleset：

```bash
sudo ./bin/agentguardian -rules /etc/agentguardian/rules.d
```

示例：

```yaml
version: 1
rules:
  - id: hide-claude-passwd
    match:
      path: /etc/passwd
      exe: /opt/claude-code/bin/claude
    action:
      type: hide

  - id: rewrite-cat-token
    match:
      path: /tmp/ag-test.txt
      comm: cat
    action:
      type: rewrite
      find: secret
      replace: public
```

说明：

- `-rules` 可以指向单个 YAML 文件，或一个 `rules.d` 目录
- 目录加载时按文件名字典序合并
- 当前规则模型要求每条规则只设置一个 selector：`pid`、`comm`、`exe` 三选一

## 守护进程模式

除了原有的单进程 CLI 模式，现在也支持 `agentguardd + agctl` 控制面。

### 1. 目录约定

```text
/etc/agentguardian/
  rules.d/
    010-hide-claude-passwd.yaml
    100-rewrite-cat-token.yaml
```

### 2. 启动 daemon

```bash
sudo ./bin/agentguardd \
  -config-dir /etc/agentguardian \
  -socket /run/agentguardian/agentguardd.sock
```

### 3. 查询状态

```bash
./bin/agctl -socket /run/agentguardian/agentguardd.sock status
```

### 4. 校验规则

校验 permanent：

```bash
./bin/agctl -socket /run/agentguardian/agentguardd.sock validate -scope permanent
```

校验 runtime：

```bash
./bin/agctl -socket /run/agentguardian/agentguardd.sock validate -scope runtime
```

### 5. 从 permanent 重载到 runtime

```bash
./bin/agctl -socket /run/agentguardian/agentguardd.sock reload
```

## Runtime / Permanent

当前控制面已经区分两套状态：

- `permanent`
  - 磁盘上的 `rules.d`
  - 是 daemon 重启后的恢复来源
- `runtime`
  - daemon 内存里当前已编译并下发到 BPF maps 的规则快照

当前支持的控制动作：

- `status`
- `validate`
- `reload`

当前还不支持：

- `save`
- `apply --runtime`
- runtime override 持久化

也就是说，目前 `reload` 的语义是：

- 重新读取 `rules.d`
- 编译为当前 `policy_map` / `comm_policy_map`
- 用 permanent 覆盖当前 runtime

## 参数说明

基础参数：

- `-rules`: YAML 规则文件或 `rules.d` 目录
- `-path`: 目标文件路径
- `-find`: 要匹配的字符串
- `-replace`: 替换字符串
- `-rewrite`: `-replace` 的兼容别名

按 PID：

- `-rewrite-pid`
- `-hide-pid`

按进程名：

- `-rewrite-comm`
- `-hide-comm`

按可执行文件：

- `-rewrite-exe`
- `-hide-exe`

说明：

- `-rewrite-*` 只有在实际启用 rewrite 时才要求 `-find/-replace`
- 纯 `hide-*` 场景不需要 `-find/-replace`
- `comm` 参数支持逗号分隔，例如 `cat,less`
- `exe` 参数支持逗号分隔，例如 `/usr/bin/cat,/usr/bin/node`

## 日志示例

启动日志：

```text
AgentGuardian active: path="/tmp/ag-test.txt" rewrite-pid=0 hide-pid=0 rewrite-comm="" hide-comm="" rewrite-exe="/usr/bin/cat" hide-exe="" find="secret" replace="public"
```

YAML 模式启动日志：

```text
AgentGuardian active: rules="/etc/agentguardian/rules.d" version=1 rule-count=2 pid-policies=1 comm-policies=1
```

事件日志：

```text
op=open action=rewrite pid=123 tid=124 ret=0 comm=cat path=/tmp/ag-test.txt
op=rewrite action=rewrite pid=123 tid=124 ret=6 comm=cat path=/tmp/ag-test.txt
op=block action=hide pid=456 tid=456 ret=-2 comm=claude path=/tmp/replacetest
```

字段含义：

- `op=open`: 命中目标文件打开
- `op=rewrite`: 实际发生内容改写
- `op=block`: 实际发生隐藏/阻断

## 测试

普通测试：

```bash
go test ./...
```

集成测试：

```bash
go test -tags=integration ./cmd/agentguardian -v
```

集成测试覆盖：

- 跨线程 `open` + `read` 的 rewrite
- `hide-exe` 阻断
- 非目标路径不改写

## 代码结构

```text
cmd/agentguardian/     CLI 入口和集成测试
cmd/agentguardd/       守护进程入口
cmd/agctl/             Unix socket 控制客户端
config/                参数解析与策略同步
internal/control/      runtime/permanent 控制面
internal/rules/        规则模型、YAML、校验、编译
internal/ebpf/         BPF 源码、bpf2go 生成物、运行时封装
example/               参考实现
doc/                   背景文档和开发记录
```

## 注意事项

- `bpf_probe_write_user` 属于高风险能力，只建议在受控环境中使用
- `hide` 功能依赖内核 LSM 支持，不是所有发行版默认可用
- 如果 `make` 因 `.o` 文件权限失败，通常是之前用 `sudo` 生成过对象文件，修正文件属主后再构建即可

## License

见 [LICENSE](LICENSE)。
