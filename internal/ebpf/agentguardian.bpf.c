//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "agentguardian.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AG_ERR_ENOENT 2
#define AG_ERR_EPERM 1
#define AG_SCAN_STAGE 0
#define AG_SCAN_CHUNK 32
#define AG_MAX_SCAN_BYTES 1024

const struct event *unused_event __attribute__((unused));
const struct policy *unused_policy __attribute__((unused));
const struct comm_key *unused_comm_key __attribute__((unused));
int scan_read_buffer(struct trace_event_raw_sys_exit *ctx);

struct pending_open {
	__u8 action;
	__u8 _pad[3];
	char path[AG_MAX_PATH_LEN];
};

struct rewrite_state {
	__u64 buf_addr;
	__u32 bytes_to_scan;
	__u32 offset;
	__u32 replacements;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct policy);
} policy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct comm_key);
	__type(value, struct policy);
} comm_policy_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct syscall_rule);
} syscall_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, struct syscall_pid_key);
	__type(value, struct syscall_rule);
} syscall_pid_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct syscall_comm_key);
	__type(value, struct syscall_rule);
} syscall_comm_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} exec_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct fd_key);
	__type(value, __u32);
} map_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} map_buff_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} closing_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct rewrite_state);
} rewrite_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__array(values, int());
} scan_prog_array SEC(".maps") = {
	.values = {
		[AG_SCAN_STAGE] = &scan_read_buffer,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int path_matches(const struct policy *policy, const char *candidate)
{
	if (!policy) {
		return 0;
	}

	if (policy->target_path[0] == '\0' || candidate[0] == '\0') {
		return 0;
	}

	#pragma unroll
	for (int i = 0; i < AG_MAX_PATH_LEN; i++) {
		if (policy->target_path[i] != candidate[i]) {
			return 0;
		}
		if (policy->target_path[i] == '\0') {
			return 1;
		}
	}

	return 0;
}

static __always_inline const struct policy *lookup_policy(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct comm_key key = {};
	const struct policy *policy;

	policy = bpf_map_lookup_elem(&policy_map, &pid);
	if (policy) {
		return policy;
	}

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	return bpf_map_lookup_elem(&comm_policy_map, &key);
}

static __always_inline void submit_event(__u32 action, __u32 op, __s32 ret, __u32 aux, const char *path)
{
	struct event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->pid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->action = action;
	event->op = op;
	event->ret = ret;
	event->aux = aux;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	if (path) {
		__builtin_memcpy(event->path, path, sizeof(event->path));
	}

	bpf_ringbuf_submit(event, 0);
}

static __always_inline void submit_syscall_event(__u32 syscall_nr, __s32 ret)
{
	submit_event(AG_ACTION_AUDIT, AG_OP_SYSCALL, ret, syscall_nr, "");
}

static __always_inline void submit_exec_event(__u32 action, __s32 ret, const char *path)
{
	submit_event(action, AG_OP_EXEC, ret, 0, path);
}

static __always_inline const struct syscall_rule *lookup_syscall_rule(__u32 syscall_nr)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct syscall_pid_key pid_key = {
		.pid = pid,
		.syscall_nr = syscall_nr,
	};
	struct syscall_comm_key comm_key = {
		.syscall_nr = syscall_nr,
	};
	const struct syscall_rule *rule;

	rule = bpf_map_lookup_elem(&syscall_pid_rules, &pid_key);
	if (rule) {
		return rule;
	}

	bpf_get_current_comm(&comm_key.comm, sizeof(comm_key.comm));
	rule = bpf_map_lookup_elem(&syscall_comm_rules, &comm_key);
	if (rule) {
		return rule;
	}

	return bpf_map_lookup_elem(&syscall_rules, &syscall_nr);
}

static __always_inline __u32 lookup_exec_mode(void)
{
	__u32 key = 0;
	__u32 *mode = bpf_map_lookup_elem(&exec_policy, &key);

	if (!mode) {
		return AG_ENFORCE_ALLOW;
	}

	return *mode;
}

static __always_inline void clear_read_state(__u64 pid_tgid)
{
	bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);
	bpf_map_delete_elem(&rewrite_states, &pid_tgid);
}

static __always_inline __u32 clamp_scan_len(__s64 read_ret)
{
	__u32 bytes_to_scan;

	if (read_ret <= 0) {
		return 0;
	}

	bytes_to_scan = (__u32)read_ret;
	if (bytes_to_scan > AG_MAX_SCAN_BYTES) {
		bytes_to_scan = AG_MAX_SCAN_BYTES;
	}

	return bytes_to_scan;
}

static __always_inline int load_rewrite_context(__u64 *pid_tgid, struct rewrite_state **state, const struct policy **policy)
{
	*pid_tgid = bpf_get_current_pid_tgid();
	*state = bpf_map_lookup_elem(&rewrite_states, pid_tgid);
	if (!*state || (*state)->buf_addr == 0 || (*state)->bytes_to_scan == 0) {
		return 0;
	}

	*policy = lookup_policy();
	if (!*policy || (*policy)->action != AG_ACTION_REWRITE || (*policy)->text_len == 0) {
		clear_read_state(*pid_tgid);
		return 0;
	}

	if ((*policy)->text_len > AG_MAX_TEXT_LEN) {
		clear_read_state(*pid_tgid);
		return 0;
	}

	return 1;
}

static __always_inline int buffer_matches_find(const struct policy *policy, __u64 addr)
{
	#pragma unroll
	for (int i = 0; i < AG_MAX_TEXT_LEN; i++) {
		char ch;

		if ((__u32)i >= policy->text_len) {
			return 1;
		}
		if (bpf_probe_read_user(&ch, sizeof(ch), (void *)(addr + i)) < 0) {
			return 0;
		}
		if (ch != policy->find[i]) {
			return 0;
		}
	}

	return 1;
}

static __always_inline void write_replace_text(const struct policy *policy, __u64 addr)
{
	#pragma unroll
	for (int i = 0; i < AG_MAX_TEXT_LEN; i++) {
		char ch;

		if ((__u32)i >= policy->text_len) {
			return;
		}

		ch = policy->replace[i];
		bpf_probe_write_user((void *)(addr + i), &ch, sizeof(ch));
	}
}

static __always_inline int scan_read_buffer_impl(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid;
	struct rewrite_state *state;
	const struct policy *policy;

	if (!load_rewrite_context(&pid_tgid, &state, &policy)) {
		return 0;
	}

	#pragma unroll
	for (int i = 0; i < AG_SCAN_CHUNK; i++) {
		__u64 candidate_addr;

		if (state->offset >= state->bytes_to_scan) {
			break;
		}

		if (state->offset + policy->text_len > state->bytes_to_scan) {
			state->offset = state->bytes_to_scan;
			break;
		}

		candidate_addr = state->buf_addr + state->offset;
		if (buffer_matches_find(policy, candidate_addr)) {
			write_replace_text(policy, candidate_addr);
			state->replacements++;
			state->offset += policy->text_len;
			continue;
		}

		state->offset++;
	}

	if (state->offset < state->bytes_to_scan) {
		bpf_tail_call(ctx, &scan_prog_array, AG_SCAN_STAGE);
	}

	if (state->replacements > 0) {
		submit_event(policy->action, AG_OP_REWRITE, state->replacements * policy->text_len, 0, policy->target_path);
	}

	clear_read_state(pid_tgid);
	return 0;
}

static __always_inline int handle_open_enter_impl(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	const struct policy *policy;
	struct pending_open pending = {0};
	long copied;

	policy = lookup_policy();
	if (!policy || policy->action == AG_ACTION_PASS) {
		return 0;
	}

	copied = bpf_probe_read_user_str(pending.path, sizeof(pending.path), (const char *)ctx->args[1]);
	if (copied <= 0) {
		return 0;
	}

	if (!path_matches(policy, pending.path)) {
		return 0;
	}

	pending.action = policy->action;
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	submit_event(policy->action, AG_OP_OPEN, 0, 0, pending.path);

	return 0;
}

static __always_inline int handle_open_exit_impl(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct pending_open *pending;
	struct fd_key fd_key = {};
	__u32 fd;
	__u32 tracked = 1;

	pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending) {
		return 0;
	}

	if (ctx->ret >= 0 && pending->action == AG_ACTION_REWRITE) {
		fd = (__u32)ctx->ret;
		fd_key.tgid = tgid;
		fd_key.fd = fd;
		bpf_map_update_elem(&map_fds, &fd_key, &tracked, BPF_ANY);
	}

	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_open_enter_impl(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit_impl(ctx);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_open_enter_impl(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int handle_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit_impl(ctx);
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending;

	if (ret) {
		return ret;
	}

	pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending || pending->action != AG_ACTION_HIDE) {
		return 0;
	}

	submit_event(pending->action, AG_OP_BLOCK, -AG_ERR_ENOENT, 0, pending->path);
	return -AG_ERR_ENOENT;
}

static __always_inline int handle_sys_enter_exec(__u64 filename_ptr)
{
	char filename[AG_MAX_PATH_LEN] = {};
	long copied;

	copied = bpf_probe_read_user_str(filename, sizeof(filename), (const char *)filename_ptr);
	if (copied <= 0) {
		return 0;
	}

	submit_exec_event(AG_ACTION_AUDIT, 0, filename);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_sys_enter_exec(ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_sys_enter_exec(ctx->args[1]);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_execve, struct linux_binprm *bprm, int ret)
{
	__u32 mode;
	const char *filename;
	char path[AG_MAX_PATH_LEN] = {};

	if (ret) {
		return ret;
	}

	mode = lookup_exec_mode();
	if (mode == AG_ENFORCE_ALLOW) {
		return 0;
	}

	filename = BPF_CORE_READ(bprm, filename);
	if (filename) {
		bpf_probe_read_kernel_str(path, sizeof(path), filename);
	}

	submit_exec_event(AG_ACTION_AUDIT, 0, path);

	if (mode == AG_ENFORCE_DENY) {
		submit_exec_event(AG_ACTION_HIDE, -AG_ERR_EPERM, path);
		return -AG_ERR_EPERM;
	}

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 syscall_nr = ctx->id;
	const struct syscall_rule *rule;

	rule = lookup_syscall_rule(syscall_nr);
	if (!rule || rule->mode == AG_ENFORCE_ALLOW) {
		return 0;
	}

	submit_syscall_event(syscall_nr, 0);
	return 0;
}

static __always_inline int handle_read_enter_impl(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct fd_key fd_key = {};
	__u32 *tracked_fd;
	__u32 fd = (__u32)ctx->args[0];
	__u64 buf_addr = ctx->args[1];

	fd_key.tgid = tgid;
	fd_key.fd = fd;
	tracked_fd = bpf_map_lookup_elem(&map_fds, &fd_key);
	if (!tracked_fd) {
		return 0;
	}

	bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buf_addr, BPF_ANY);
	return 0;
}

static __always_inline int prepare_read_rewrite_state(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *buf_addr;
	const struct policy *policy;
	struct rewrite_state state = {};

	buf_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
	if (!buf_addr) {
		return 0;
	}

	policy = lookup_policy();
	if (!policy || policy->action != AG_ACTION_REWRITE || policy->text_len == 0 || policy->text_len > AG_MAX_TEXT_LEN) {
		clear_read_state(pid_tgid);
		return 0;
	}

	state.buf_addr = *buf_addr;
	state.bytes_to_scan = clamp_scan_len(ctx->ret);
	if (state.bytes_to_scan < policy->text_len) {
		clear_read_state(pid_tgid);
		return 0;
	}

	bpf_map_update_elem(&rewrite_states, &pid_tgid, &state, BPF_ANY);
	return 1;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_read_enter_impl(ctx);
}

static __always_inline int handle_read_exit_impl(struct trace_event_raw_sys_exit *ctx)
{
	if (!prepare_read_rewrite_state(ctx)) {
		return 0;
	}

	return scan_read_buffer_impl(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_read_exit_impl(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int scan_read_buffer(struct trace_event_raw_sys_exit *ctx)
{
	return scan_read_buffer_impl(ctx);
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct fd_key fd_key = {};
	__u32 *tracked_fd;
	__u32 fd = (__u32)ctx->args[0];

	fd_key.tgid = tgid;
	fd_key.fd = fd;
	tracked_fd = bpf_map_lookup_elem(&map_fds, &fd_key);
	if (!tracked_fd) {
		return 0;
	}

	bpf_map_update_elem(&closing_fds, &pid_tgid, &fd, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct fd_key fd_key = {};
	__u32 *fd;

	fd = bpf_map_lookup_elem(&closing_fds, &pid_tgid);
	if (!fd) {
		return 0;
	}

	fd_key.tgid = tgid;
	fd_key.fd = *fd;
	bpf_map_delete_elem(&closing_fds, &pid_tgid);
	bpf_map_delete_elem(&map_fds, &fd_key);
	bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);
	return 0;
}
