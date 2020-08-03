#include <linux/file.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bpf.h>

#define ARGSIZE 128
#define bpf_probe_read_user bpf_probe_read

BPF_PERF_OUTPUT(events);

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  
    u32 ppid; 
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int probe_execve_enter (struct pt_regs *ctx, const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp) {

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    // submit_arg(ctx, (void *)filename, &data);
    events.perf_submit(ctx, &data, sizeof(data));

    // Unroll loops -- not allowed in eBPF programs.
    #pragma unroll
    for (int i=1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
            return 0;
    }


    return 0;
}
