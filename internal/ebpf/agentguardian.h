#ifndef __AGENT_GUARDIAN_H__
#define __AGENT_GUARDIAN_H__

#define AG_MAX_PATH_LEN 64
#define AG_MAX_TEXT_LEN 64
#define AG_TASK_COMM_LEN 16

enum ag_action {
	AG_ACTION_PASS = 0,
	AG_ACTION_AUDIT = 1,
	AG_ACTION_HIDE = 2,
	AG_ACTION_REWRITE = 3,
};

enum ag_operation {
	AG_OP_OPEN = 1,
	AG_OP_BLOCK = 2,
	AG_OP_REWRITE = 3,
	AG_OP_EXEC = 4,
	AG_OP_SYSCALL = 5,
};

enum ag_enforce_mode {
	AG_ENFORCE_ALLOW = 0,
	AG_ENFORCE_AUDIT = 1,
	AG_ENFORCE_DENY = 2,
};

struct syscall_rule {
	__u32 syscall_nr;
	__u32 mode;
};

struct syscall_pid_key {
	__u32 pid;
	__u32 syscall_nr;
};

struct syscall_comm_key {
	char comm[AG_TASK_COMM_LEN];
	__u32 syscall_nr;
};

struct policy {
	__u8 action;
	__u8 _pad[3];
	char target_path[AG_MAX_PATH_LEN];
	__u32 text_len;
	char find[AG_MAX_TEXT_LEN];
	char replace[AG_MAX_TEXT_LEN];
};

struct comm_key {
	char comm[AG_TASK_COMM_LEN];
};

struct fd_key {
	__u32 tgid;
	__u32 fd;
};

struct event {
	__u32 pid;
	__u32 tid;
	__u32 action;
	__u32 op;
	__s32 ret;
	__u32 aux;
	char comm[AG_TASK_COMM_LEN];
	char path[AG_MAX_PATH_LEN];
};

#endif
