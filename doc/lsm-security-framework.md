# LSM / Execve / Dangerous Syscall Framework

当前已经不只是空骨架，仓库里已经内置了一套默认的危险 syscall 审计规则。

目标：
- 在现有 `file_open` 隐藏能力之外，预留更通用的 LSM 拦截入口
- 对 `execve` 增加独立的审计/阻断挂载点
- 对“危险 syscall”增加统一记录入口

## 放置位置

内核态：
- `internal/ebpf/agentguardian.bpf.c`
- `internal/ebpf/agentguardian.h`

用户态：
- `internal/ebpf/runtime.go`
- `internal/ebpf/security.go`

## 当前预留的挂载点

1. `SEC("lsm/file_open")`
- 现有能力
- 适合做文件访问阻断

2. `SEC("lsm/bprm_check_security")`
- 新增骨架
- 适合做 `execve` 审计和阻断
- 后续可在这里补：
  - 可执行文件白名单/黑名单
  - 父进程、命令行、cgroup、namespace 条件判断

3. `SEC("tracepoint/raw_syscalls/sys_enter")`
- 新增骨架
- 适合统一记录危险 syscall 进入事件
- 这里只做审计，不直接阻断

4. `SEC("tracepoint/syscalls/sys_enter_execve")`
5. `SEC("tracepoint/syscalls/sys_enter_execveat")`
- 新增骨架
- 用于补充 exec 进入前的路径记录

## 当前预留的 map

1. `syscall_rules`
- key: syscall number
- value: `struct syscall_rule`
- 用于标记某个 syscall 是 `allow/audit/deny`
- 当前默认 profile 已经写入一批 `audit` 规则
- 当前内核态实现对这批规则的处理方式是：
  - 在 `tracepoint/raw_syscalls/sys_enter` 上记录命中事件
  - 将 syscall number 写入 event 的 `aux` 字段
  - 用户态日志再将 `aux` 翻译成 syscall 名称
- 当前不会仅凭这条 tracepoint 直接阻断 syscall

1. `syscall_pid_rules`
- key: `struct syscall_pid_key { pid, syscall_nr }`
- value: `struct syscall_rule`
- 用于把某个 syscall 只限定到指定 PID 生效

2. `syscall_comm_rules`
- key: `struct syscall_comm_key { comm, syscall_nr }`
- value: `struct syscall_rule`
- 用于把某个 syscall 只限定到指定进程名生效

3. `exec_policy`
- 单元素 array map
- key 固定为 `0`
- value 为 `allow/audit/deny`
- 用于控制 `execve` 的全局模式

## 当前预留的用户态入口

文件：[security.go](/home/xiu/GolandProjects/agentguardian/internal/ebpf/security.go)

- `SetExecMode(...)`
- `PutSyscallRule(...)`
- `DeleteSyscallRule(...)`
- `ReplaceSyscallRules(...)`
- `ApplySecurityProfile(...)`
- `DefaultSecurityProfile(...)`
- `SyscallName(...)`

## 当前支持的作用域

`syscall_rules` 现在支持三种作用域：

1. `pid`
- 只对指定 PID 生效
- 适合临时隔离单个高风险进程

2. `comm`
- 只对指定进程名生效
- 适合限制 `bash`、`python`、`node`、`claude` 这类稳定进程名

3. `exe`
- 只对指定可执行文件路径生效
- 用户态会扫描 `/proc/*/exe`，把命中的进程展开成 `pid` 规则
- 因为进程会变化，所以需要后台周期同步

优先级：
- `pid` 规则优先于 `comm`
- `comm` 规则优先于全局 `syscall_rules`
- `exe` 在用户态被展开成 `pid` 规则，因此实际优先级等同于 `pid`

## 当前默认危险 syscall 规则的作用

文件：[security.go](/home/xiu/GolandProjects/agentguardian/internal/ebpf/security.go)

默认 profile 会把以下 syscall 放进 `syscall_rules`，模式均为 `audit`：

1. 内核与观测能力
- `bpf`
- `perf_event_open`
- `io_uring_setup`

作用：
- 识别进程是否在尝试申请更强的内核观测、注入或异步执行能力
- 这类调用常见于逃逸探测、内核态探针、低层监控与规避行为

2. 跨进程读写与调试能力
- `ptrace`
- `process_vm_readv`
- `process_vm_writev`

作用：
- 识别进程是否尝试读取、修改或调试其他进程地址空间
- 这通常意味着更高风险的数据窃取、注入或控制企图

3. 模块与内核装载能力
- `init_module`
- `finit_module`
- `delete_module`
- `kexec_load`

作用：
- 识别进程是否尝试装载/卸载内核模块，或替换内核启动映像
- 这是高危提权和持久化行为的强信号

4. 挂载与文件系统拓扑变更能力
- `mount`
- `umount2`
- `pivot_root`
- `open_tree`
- `move_mount`
- `fsopen`
- `fsconfig`
- `fsmount`
- `fspick`
- `open_by_handle_at`
- `name_to_handle_at`

作用：
- 识别进程是否在尝试绕过常规路径访问控制，或重构挂载视图
- 这些 syscall 常用于 namespace 操作、容器逃逸辅助、路径绕过和隐蔽访问

5. namespace 与环境隔离控制
- `setns`
- `unshare`

作用：
- 识别进程是否切换或拆分 namespace
- 这通常和容器边界穿透、隔离规避、沙箱逃避有关

6. 文件系统与系统级监控能力
- `fanotify_init`
- `fanotify_mark`

作用：
- 识别进程是否试图建立大范围文件访问监听
- 这可能意味着敏感文件监控、批量采集或反取证观察

7. 系统状态与凭据相关能力
- `swapon`
- `swapoff`
- `reboot`
- `add_key`
- `request_key`
- `keyctl`

作用：
- 识别进程是否在尝试改动系统级运行状态或 Linux keyring
- 这类行为往往不属于普通业务进程，应当优先进入审计视野

## 当前实际生效方式

当前这批 `syscall_rules` 的具体效果不是“自动拦截”，而是“统一审计并打点”：

1. 进程进入被标记的 syscall
2. `tracepoint/raw_syscalls/sys_enter` 命中规则
3. eBPF 向 ringbuf 发送 `op=syscall` 事件
4. `event.aux` 携带 syscall number
5. 用户态日志输出 syscall 编号与名称

因此它当前的价值主要体现在：
- 为后续精细阻断提供先验观测数据
- 建立高危行为画像
- 辅助判断某个 Agent/进程是否在尝试提权、逃逸、注入、跨进程读取或重构挂载空间

## 当前边界

- `syscall_rules` 当前默认全部是 `audit`
- 这批规则目前不会直接返回错误码给调用进程
- 如果要对某个 syscall 做真正阻断，必须选择对应的可执行阻断的内核安全点，而不是继续停留在 tracepoint
