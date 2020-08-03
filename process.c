#include <linux/file.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;  
    u32 ppid; 
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

int probe_execve_enter (struct pt_regs *ctx, const char __user $filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp) {

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
