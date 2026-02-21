#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/binfmts.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROCFS_NAME "ept_target"
static char target_comm[16] = ""; 

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    int len = min(count, (size_t)sizeof(target_comm) - 1);
    
    if (copy_from_user(target_comm, ubuf, len))
        return -EFAULT;

    target_comm[len] = '\0';
    
    if (len > 0 && target_comm[len - 1] == '\n')
        target_comm[len - 1] = '\0';

    printk(KERN_INFO "EPT_PROBE: Now watching for program: %s\n", target_comm);
    return count;
}

static const struct proc_ops ept_proc_ops = {
    .proc_write = proc_write,
};
static int handler_execve_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct task_struct *task = current;
    
    // Print EVERY process that successfully executes
    if (regs->ax == 0) {
        printk(KERN_INFO "EPT_PROBE: Executed %s [PID: %d]\n", task->comm, task->pid);
        
        // Keep your original check inside
        if (target_comm[0] != '\0' && strcmp(task->comm, target_comm) == 0) {
            unsigned long cr3 = __pa(task->mm->pgd);
            printk(KERN_INFO "EPT_PROBE: Target MATCH! CR3: 0x%lx\n", cr3);
            
            asm volatile(
                "vmcall\n\t"
                : : "a" (0x1337), "b" (cr3) : "memory"
            );
            printk(KERN_INFO "EPT_PROBE: VMCALL executed.\n");
        }
    }
    return 0;
}
static struct kretprobe my_kretprobe = {
    .handler = handler_execve_return,
    .kp.symbol_name = "bprm_execve",
    .maxactive = 20,
};

static int __init ept_probe_init(void)
{
    // Create the /proc entry
    if (!proc_create(PROCFS_NAME, 0666, NULL, &ept_proc_ops)) {
        return -ENOMEM;
    }

    // Register the kprobe
    int ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        remove_proc_entry(PROCFS_NAME, NULL);
        return ret;
    }
    
    printk(KERN_INFO "EPT_PROBE: Initialized. Write to /proc/%s to set target.\n", PROCFS_NAME);
    return 0;
}

static void __exit ept_probe_exit(void)
{
    unregister_kretprobe(&my_kretprobe);
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "EPT_PROBE: Removed.\n");
}

module_init(ept_probe_init);
module_exit(ept_probe_exit);
MODULE_AUTHOR("Jake Klocker");
MODULE_DESCRIPTION("EPT CR3 capture probe for target processes");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");