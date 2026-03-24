#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/pgtable.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/spinlock.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/tracepoint.h>
#include <linux/uprobes.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/debugreg.h>
#include <asm/processor.h>
#include "memreader_ioctl.h"

#define DEVICE_NAME "memreader"
#define CLASS_NAME "memreader"
#define MAX_BREAKPOINTS 4
#define MAX_HIT_RECORDS 64

// Input validation limits
#define MAX_READ_SIZE (16 * 1024 * 1024)  // 16 MB max single read
#define MIN_READ_SIZE 1

// Page status codes for diagnostics
enum page_status {
    PAGE_STATUS_OK = 0,         // Page present and readable
    PAGE_STATUS_NOT_ALLOCATED,  // Page never allocated (pte_none)
    PAGE_STATUS_NOT_PRESENT,    // Page exists but not in RAM (swapped/migrating/etc)
    PAGE_STATUS_NO_PGD,         // PGD entry missing
    PAGE_STATUS_NO_P4D,         // P4D entry missing
    PAGE_STATUS_NO_PUD,         // PUD entry missing
    PAGE_STATUS_NO_PMD,         // PMD entry missing
    PAGE_STATUS_NO_PTE,         // PTE lookup failed
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Learning Project");
MODULE_DESCRIPTION("Kernel-level process memory reader with page decryption monitor, syscall tracing, and decrypt hook");
MODULE_VERSION("2.4");

static int major_number;
static struct class* memreader_class = NULL;
static struct device* memreader_device = NULL;

// ============================================================================
// Hardware Breakpoint State
// ============================================================================

struct bp_hit_record {
    int valid;
    int pid;
    int bp_num;
    unsigned long rip;
    unsigned long rsp;
    unsigned long fault_addr;
    unsigned long dr6;
    unsigned long timestamp;
};

struct active_breakpoint {
    int active;
    int pid;
    unsigned long address;
    int type;
    int len;
    struct perf_event *bp_event;  // Per-task breakpoint (not __percpu)
};

static struct active_breakpoint breakpoints[MAX_BREAKPOINTS];
static struct bp_hit_record hit_records[MAX_HIT_RECORDS];
static int hit_record_head = 0;
static DEFINE_SPINLOCK(bp_lock);

// ============================================================================
// Page Decryption Monitor State
// ============================================================================

struct page_watch_entry {
    unsigned long address;          // Page address
    uint8_t signature[16];          // First 16 bytes for comparison
    int changed;                    // Set when page content changes
};

struct page_monitor_state {
    int active;
    int pid;
    int num_pages;
    int poll_interval_us;
    struct page_watch_entry *pages;     // Dynamically allocated
    struct task_struct *monitor_thread;
    unsigned long poll_count;
    unsigned long pages_changed;

    // Ring buffer of captures
    int capture_head;                   // Next write position
    int capture_count;                  // Number of captures stored
    struct memreader_capture_event *captures;  // Dynamically allocated
};

static struct page_monitor_state monitor_state;
static DEFINE_MUTEX(monitor_mutex);

// ============================================================================
// Syscall Tracing State
// ============================================================================

struct syscall_trace_state {
    int active;
    int target_pid;                 // 0 = trace all
    int trace_entries;
    int trace_exits;

    // Ring buffer
    struct memreader_syscall_entry *buffer;
    int head;                       // Next write position
    int tail;                       // Next read position
    int count;                      // Number of entries in buffer
    int overflow;                   // Set if we dropped entries

    unsigned long total_syscalls;
    unsigned long dropped;
};

static struct syscall_trace_state syscall_state;
static DEFINE_SPINLOCK(syscall_lock);
static struct tracepoint *tp_sys_enter = NULL;

// ============================================================================
// Uprobe State
// ============================================================================

#define MAX_UPROBES 8

struct uprobe_hit_record {
    unsigned long timestamp;
    int tid;
    unsigned long rip;
    unsigned long rax, rbx, rcx, rdx;
    unsigned long rsi, rdi, rbp, rsp;
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;
};

struct active_uprobe {
    int active;
    int pid;
    unsigned long address;          // Virtual address
    unsigned long file_offset;      // File offset for uprobe registration
    struct inode *inode;            // Inode of the mapped file
    struct uprobe *uprobe;          // Returned by uprobe_register
    struct uprobe_consumer consumer;

    // Ring buffer of hits
    struct uprobe_hit_record *hits;
    int head;                       // Next write position
    int count;                      // Number of entries
    int overflow;
    unsigned long total_hits;
};

static struct active_uprobe uprobes[MAX_UPROBES];
static DEFINE_SPINLOCK(uprobe_lock);

// ============================================================================
// Decrypt Hook State (Hardware Breakpoint for JIT code)
// ============================================================================

#define MAX_THREAD_BREAKPOINTS 512

struct decrypt_hook_state {
    int active;
    int pid;
    int tid;                            // 0 = capture all threads
    unsigned long address;

    // Per-thread breakpoints (hardware breakpoints are per-thread)
    struct perf_event *bp_events[MAX_THREAD_BREAKPOINTS];
    int bp_tids[MAX_THREAD_BREAKPOINTS];  // TID for each breakpoint
    int num_breakpoints;

    // Ring buffer of captures
    struct memreader_decrypt_entry *entries;
    int head;                           // Next write position
    int count;                          // Current entries in buffer
    int overflow;
    unsigned long total_captures;
};

static struct decrypt_hook_state decrypt_hook;
static DEFINE_SPINLOCK(decrypt_hook_lock);

// ============================================================================
// Kallsyms Lookup Helper
// ============================================================================
//
// Since Linux 5.7, kallsyms_lookup_name() is no longer exported to modules.
// This is a deliberate security measure to prevent modules from easily
// finding and hooking arbitrary kernel functions.
//
// For legitimate use cases (like this module needing to find tracepoints),
// we use a kprobe-based technique: kprobes can still look up symbols by name,
// so we register a temporary kprobe on kallsyms_lookup_name, extract its
// address, then unregister immediately.
//
// Alternative approaches that DON'T work on modern kernels:
// - Direct kallsyms_lookup_name() call: not exported since 5.7
// - /proc/kallsyms parsing: requires root and is slow
// - kprobe_lookup_name(): internal API, not exported
//

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;
static DEFINE_MUTEX(kallsyms_init_mutex);
static bool kallsyms_init_attempted = false;

static int kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    return 0;  // Do nothing - we just need the address
}

/**
 * init_kallsyms_lookup - Initialize kallsyms_lookup_name function pointer
 *
 * Uses the kprobe technique to find kallsyms_lookup_name address.
 * This is safe to call multiple times - initialization only happens once.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int init_kallsyms_lookup(void) {
    struct kprobe kp;
    int ret;
    unsigned long addr;

    mutex_lock(&kallsyms_init_mutex);

    // Already initialized successfully?
    if (my_kallsyms_lookup_name) {
        mutex_unlock(&kallsyms_init_mutex);
        return 0;
    }

    // Already tried and failed?
    if (kallsyms_init_attempted) {
        mutex_unlock(&kallsyms_init_mutex);
        return -ENOENT;
    }

    kallsyms_init_attempted = true;

    // Set up a temporary kprobe on kallsyms_lookup_name
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    kp.pre_handler = kprobe_pre_handler;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "MemReader: Failed to register kprobe for kallsyms_lookup_name: %d\n", ret);
        printk(KERN_ERR "MemReader: This may indicate kprobes is disabled or symbol not found\n");
        mutex_unlock(&kallsyms_init_mutex);
        return ret;
    }

    // Extract the resolved address
    addr = (unsigned long)kp.addr;
    if (!addr) {
        printk(KERN_ERR "MemReader: kprobe registered but address is NULL\n");
        unregister_kprobe(&kp);
        mutex_unlock(&kallsyms_init_mutex);
        return -EFAULT;
    }

    // We have the address - unregister the kprobe immediately
    unregister_kprobe(&kp);

    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
    printk(KERN_INFO "MemReader: Found kallsyms_lookup_name at 0x%lx\n", addr);

    mutex_unlock(&kallsyms_init_mutex);
    return 0;
}

/**
 * lookup_symbol - Look up a kernel symbol by name
 * @name: Symbol name to look up
 *
 * Returns: Symbol address, or 0 if not found or lookup unavailable
 */
static unsigned long lookup_symbol(const char *name) {
    int ret;

    ret = init_kallsyms_lookup();
    if (ret < 0) {
        return 0;
    }

    return my_kallsyms_lookup_name(name);
}

// ============================================================================
// access_remote_vm function pointer (not exported to modules)
// ============================================================================

typedef int (*access_remote_vm_t)(struct mm_struct *mm, unsigned long addr,
                                  void *buf, int len, unsigned int gup_flags);
static access_remote_vm_t fn_access_remote_vm = NULL;

// ============================================================================
// Process/Task Helpers
// ============================================================================

// Find process by PID
static struct task_struct* get_task_by_pid(int pid) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    return task;
}

// Find thread by TID within a process
static struct task_struct* get_thread_by_tid(int pid, int tid) {
    struct task_struct *task, *thread;
    struct pid *pid_struct;

    if (tid == 0) {
        // tid=0 means main thread
        return get_task_by_pid(pid);
    }

    pid_struct = find_get_pid(tid);
    if (!pid_struct) {
        return NULL;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    if (!task) {
        return NULL;
    }

    // Verify this thread belongs to the specified process
    thread = task;
    if (thread->tgid != pid) {
        put_task_struct(task);
        return NULL;
    }

    return task;
}

// ============================================================================
// Page Table Walking (existing functionality)
// ============================================================================

/**
 * virt_to_phys_manual - Walk page tables to translate virtual to physical address
 * @mm: The mm_struct of the target process
 * @vaddr: Virtual address to translate
 * @status: Output parameter for page status (why translation failed, if it did)
 *
 * Returns: Physical address on success, 0 on failure (check status for reason)
 *
 * LOCKING: Caller MUST hold mmap_read_lock(mm) or mmap_write_lock(mm).
 *          Page tables can change without this lock, leading to use-after-free
 *          or incorrect translations.
 */
static unsigned long virt_to_phys_manual(struct mm_struct *mm, unsigned long vaddr,
                                          enum page_status *status) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t pte_val;
    unsigned long phys_addr = 0;
    unsigned long page_offset;

    lockdep_assert_held(&mm->mmap_lock);

    page_offset = vaddr & ~PAGE_MASK;

    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        *status = PAGE_STATUS_NO_PGD;
        return 0;
    }

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        *status = PAGE_STATUS_NO_P4D;
        return 0;
    }

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        *status = PAGE_STATUS_NO_PUD;
        return 0;
    }

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        *status = PAGE_STATUS_NO_PMD;
        return 0;
    }

    if (pmd_leaf(*pmd)) {
        phys_addr = (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_MASK);
        *status = PAGE_STATUS_OK;
        return phys_addr;
    }

    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte) {
        *status = PAGE_STATUS_NO_PTE;
        return 0;
    }

    pte_val = ptep_get(pte);

    if (pte_none(pte_val)) {
        *status = PAGE_STATUS_NOT_ALLOCATED;
        return 0;
    }

    if (!pte_present(pte_val)) {
        *status = PAGE_STATUS_NOT_PRESENT;
        return 0;
    }

    phys_addr = (pte_pfn(pte_val) << PAGE_SHIFT) | page_offset;
    *status = PAGE_STATUS_OK;

    return phys_addr;
}

// Read directly from physical memory
static bool read_physical_memory(unsigned long phys_addr, void *buffer, size_t size) {
    struct page *page;
    void *virt_addr;
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;

    if (!pfn_valid(pfn)) {
        return false;
    }

    page = pfn_to_page(pfn);
    if (!page) {
        return false;
    }

    virt_addr = kmap_local_page(page);
    if (!virt_addr) {
        return false;
    }

    memcpy(buffer, (char *)virt_addr + offset, size);
    kunmap_local(virt_addr);

    return true;
}

// Read memory from target process using access_remote_vm (preferred)
// or fall back to page table walking if unavailable.
// access_remote_vm properly handles file-backed and shared mappings (Wine/Proton tmpmap)
static long read_process_memory(int pid, unsigned long addr, void __user *user_buffer, unsigned long size) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buffer;
    long ret = 0;

    // Input validation
    if (size < MIN_READ_SIZE || size > MAX_READ_SIZE) {
        return -EINVAL;
    }
    if (!user_buffer) {
        return -EFAULT;
    }
    if (pid <= 0) {
        return -EINVAL;
    }
    // Check for address overflow
    if (addr + size < addr) {
        return -EINVAL;
    }

    kernel_buffer = kmalloc(size, GFP_KERNEL);
    if (!kernel_buffer) {
        return -ENOMEM;
    }

    task = get_task_by_pid(pid);
    if (!task) {
        kfree(kernel_buffer);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        kfree(kernel_buffer);
        return -EINVAL;
    }

    // Use access_remote_vm if available (handles shared mappings, Wine tmpmap, etc.)
    if (fn_access_remote_vm) {
        int bytes_read;

        // FOLL_FORCE allows reading even without explicit read permission in VMA
        bytes_read = fn_access_remote_vm(mm, addr, kernel_buffer, size, FOLL_FORCE);

        if (bytes_read <= 0) {
            printk_ratelimited(KERN_DEBUG "MemReader: access_remote_vm failed for pid=%d addr=0x%lx size=%lu\n",
                               pid, addr, size);
            memset(kernel_buffer, 0, size);
        } else if ((unsigned long)bytes_read < size) {
            printk_ratelimited(KERN_DEBUG "MemReader: partial read for pid=%d addr=0x%lx: %d of %lu bytes\n",
                               pid, addr, bytes_read, size);
            memset((char *)kernel_buffer + bytes_read, 0, size - bytes_read);
        }
    } else {
        // Fallback: manual page table walking (doesn't work for shared file mappings)
        unsigned long offset = 0;
        unsigned long pages_not_present = 0;
        unsigned long pages_not_allocated = 0;

        mmap_read_lock(mm);

        while (offset < size) {
            unsigned long vaddr = addr + offset;
            unsigned long phys_addr;
            unsigned long page_offset = vaddr & ~PAGE_MASK;
            unsigned long bytes_to_read = min(size - offset, PAGE_SIZE - page_offset);
            enum page_status status;

            phys_addr = virt_to_phys_manual(mm, vaddr, &status);

            if (phys_addr == 0) {
                switch (status) {
                    case PAGE_STATUS_NOT_PRESENT:
                        pages_not_present++;
                        break;
                    case PAGE_STATUS_NOT_ALLOCATED:
                        pages_not_allocated++;
                        break;
                    default:
                        break;
                }
                memset((char *)kernel_buffer + offset, 0, bytes_to_read);
            } else {
                if (!read_physical_memory(phys_addr, (char *)kernel_buffer + offset, bytes_to_read)) {
                    memset((char *)kernel_buffer + offset, 0, bytes_to_read);
                }
            }

            offset += bytes_to_read;
        }

        mmap_read_unlock(mm);

        if (pages_not_present > 0 || pages_not_allocated > 0) {
            printk_ratelimited(KERN_DEBUG "MemReader: pid=%d addr=0x%lx size=%lu: "
                               "%lu pages not present, %lu not allocated\n",
                               pid, addr, size, pages_not_present, pages_not_allocated);
        }
    }

    if (copy_to_user(user_buffer, kernel_buffer, size)) {
        ret = -EFAULT;
    } else {
        ret = size;
    }

    mmput(mm);
    put_task_struct(task);
    kfree(kernel_buffer);

    return ret;
}

// Get base address of main executable
static long get_process_base(int pid, unsigned long *base_addr) {
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long base = 0;

    // Input validation
    if (pid <= 0) {
        return -EINVAL;
    }
    if (!base_addr) {
        return -EINVAL;
    }

    task = get_task_by_pid(pid);
    if (!task) {
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    mmap_read_lock(mm);

    if (mm->exe_file && mm->exe_file->f_path.dentry) {
        struct vm_area_struct *vma;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
#else
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
            if (vma->vm_file == mm->exe_file && (vma->vm_flags & VM_EXEC)) {
                base = vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);

    *base_addr = base;

    mmput(mm);
    put_task_struct(task);

    return base ? 0 : -ENOENT;
}

// ============================================================================
// Hardware Breakpoint Implementation
// ============================================================================

// Breakpoint handler callback
static void bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    unsigned long flags;
    int i, slot;
    int target_pid = -1;
    int bp_num = -1;

    // Find which breakpoint this is by matching the event pointer
    spin_lock_irqsave(&bp_lock, flags);

    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (breakpoints[i].active && breakpoints[i].bp_event == bp) {
            target_pid = breakpoints[i].pid;
            bp_num = i;
            break;
        }
    }

    if (bp_num >= 0) {
        // Record the hit in circular buffer
        slot = hit_record_head;
        hit_record_head = (hit_record_head + 1) % MAX_HIT_RECORDS;

        hit_records[slot].valid = 1;
        hit_records[slot].pid = target_pid;
        hit_records[slot].bp_num = bp_num;
        hit_records[slot].rip = regs->ip;
        hit_records[slot].rsp = regs->sp;
        hit_records[slot].fault_addr = breakpoints[bp_num].address;
        hit_records[slot].dr6 = 1 << bp_num;  // Simulated DR6
        hit_records[slot].timestamp = jiffies;

        printk_ratelimited(KERN_INFO "MemReader: BP%d hit! PID=%d RIP=0x%lx RSP=0x%lx ADDR=0x%lx\n",
               bp_num, target_pid, regs->ip, regs->sp, breakpoints[bp_num].address);
    }

    spin_unlock_irqrestore(&bp_lock, flags);
}

// Set hardware breakpoint
static long set_hardware_breakpoint(struct memreader_hwbp_request *req) {
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *bp_event;
    unsigned long flags;
    int bp_num = req->bp_num;

    // Input validation
    if (bp_num < 0 || bp_num >= MAX_BREAKPOINTS) {
        return -EINVAL;
    }
    if (req->pid <= 0) {
        return -EINVAL;
    }
    if (req->address == 0) {
        return -EINVAL;
    }
    // Validate type
    if (req->type != HWBP_TYPE_EXEC &&
        req->type != HWBP_TYPE_WRITE &&
        req->type != HWBP_TYPE_READWRITE) {
        return -EINVAL;
    }
    // Validate len for data breakpoints
    if (req->type != HWBP_TYPE_EXEC) {
        if (req->len != HWBP_LEN_1 && req->len != HWBP_LEN_2 &&
            req->len != HWBP_LEN_4 && req->len != HWBP_LEN_8) {
            return -EINVAL;
        }
    }

    // Find target process
    task = get_task_by_pid(req->pid);
    if (!task) {
        return -ESRCH;
    }

    // Check if breakpoint slot is already in use
    spin_lock_irqsave(&bp_lock, flags);
    if (breakpoints[bp_num].active) {
        spin_unlock_irqrestore(&bp_lock, flags);
        put_task_struct(task);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&bp_lock, flags);

    // Initialize perf event attributes
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.pinned = 1;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.bp_addr = req->address;

    // Set breakpoint type
    switch (req->type) {
        case HWBP_TYPE_EXEC:
            attr.bp_type = HW_BREAKPOINT_X;
            attr.bp_len = sizeof(long);  // Execution BP always uses long
            break;
        case HWBP_TYPE_WRITE:
            attr.bp_type = HW_BREAKPOINT_W;
            goto set_len;
        case HWBP_TYPE_READWRITE:
            attr.bp_type = HW_BREAKPOINT_RW;
set_len:
            switch (req->len) {
                case HWBP_LEN_1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
                case HWBP_LEN_2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
                case HWBP_LEN_4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
                case HWBP_LEN_8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
                default: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
            }
            break;
        default:
            put_task_struct(task);
            return -EINVAL;
    }

    // Register per-task breakpoint (only fires for this specific task)
    bp_event = register_user_hw_breakpoint(&attr, bp_handler, NULL, task);
    if (IS_ERR(bp_event)) {
        long err = PTR_ERR(bp_event);
        printk(KERN_WARNING "MemReader: Failed to register hw breakpoint: %ld\n", err);
        put_task_struct(task);
        return err;
    }

    // Store breakpoint info
    spin_lock_irqsave(&bp_lock, flags);
    breakpoints[bp_num].active = 1;
    breakpoints[bp_num].pid = req->pid;
    breakpoints[bp_num].address = req->address;
    breakpoints[bp_num].type = req->type;
    breakpoints[bp_num].len = req->len;
    breakpoints[bp_num].bp_event = bp_event;
    spin_unlock_irqrestore(&bp_lock, flags);

    put_task_struct(task);

    printk(KERN_INFO "MemReader: Set BP%d on addr 0x%lx for PID %d\n",
           bp_num, req->address, req->pid);

    return 0;
}

// Clear hardware breakpoint
static long clear_hardware_breakpoint(struct memreader_hwbp_request *req) {
    unsigned long flags;
    int bp_num = req->bp_num;
    struct perf_event *bp_event = NULL;

    if (bp_num < 0 || bp_num >= MAX_BREAKPOINTS) {
        return -EINVAL;
    }

    spin_lock_irqsave(&bp_lock, flags);

    if (!breakpoints[bp_num].active) {
        spin_unlock_irqrestore(&bp_lock, flags);
        return -ENOENT;
    }

    bp_event = breakpoints[bp_num].bp_event;
    breakpoints[bp_num].active = 0;
    breakpoints[bp_num].bp_event = NULL;

    spin_unlock_irqrestore(&bp_lock, flags);

    if (bp_event) {
        unregister_hw_breakpoint(bp_event);
    }

    printk(KERN_INFO "MemReader: Cleared BP%d\n", bp_num);

    return 0;
}

// Get breakpoint hit info
static long get_breakpoint_hit(struct memreader_bp_hit_info *info) {
    unsigned long flags;
    int i;
    int found = 0;

    spin_lock_irqsave(&bp_lock, flags);

    // Search for hits matching the PID
    for (i = 0; i < MAX_HIT_RECORDS; i++) {
        if (hit_records[i].valid &&
            (info->pid == 0 || hit_records[i].pid == info->pid)) {
            info->hit = 1;
            info->bp_num = hit_records[i].bp_num;
            info->rip = hit_records[i].rip;
            info->rsp = hit_records[i].rsp;
            info->fault_addr = hit_records[i].fault_addr;
            info->dr6 = hit_records[i].dr6;
            info->timestamp = hit_records[i].timestamp;
            found = 1;
            break;
        }
    }

    if (!found) {
        info->hit = 0;
    }

    spin_unlock_irqrestore(&bp_lock, flags);

    return 0;
}

// Clear breakpoint hit record
static long clear_breakpoint_hit(struct memreader_bp_hit_info *info) {
    unsigned long flags;
    int i;

    spin_lock_irqsave(&bp_lock, flags);

    for (i = 0; i < MAX_HIT_RECORDS; i++) {
        if (hit_records[i].valid &&
            (info->pid == 0 || hit_records[i].pid == info->pid)) {
            hit_records[i].valid = 0;
        }
    }

    spin_unlock_irqrestore(&bp_lock, flags);

    return 0;
}

// ============================================================================
// Thread Register Reading
// ============================================================================

static long read_thread_registers(struct memreader_regs_request *req) {
    struct task_struct *task;
    struct pt_regs *regs;

    task = get_thread_by_tid(req->pid, req->tid);
    if (!task) {
        return -ESRCH;
    }

    // Get task's register state
    regs = task_pt_regs(task);
    if (!regs) {
        put_task_struct(task);
        return -EINVAL;
    }

    // Copy registers to request structure
    req->rip = regs->ip;
    req->rsp = regs->sp;
    req->rbp = regs->bp;
    req->rax = regs->ax;
    req->rbx = regs->bx;
    req->rcx = regs->cx;
    req->rdx = regs->dx;
    req->rsi = regs->si;
    req->rdi = regs->di;
    req->r8 = regs->r8;
    req->r9 = regs->r9;
    req->r10 = regs->r10;
    req->r11 = regs->r11;
    req->r12 = regs->r12;
    req->r13 = regs->r13;
    req->r14 = regs->r14;
    req->r15 = regs->r15;
    req->rflags = regs->flags;
    req->cs = regs->cs;
    req->ss = regs->ss;

    // Read FS/GS base from task->thread structure
    // On x86_64, these are stored in thread.fsbase and thread.gsbase
    req->fs_base = task->thread.fsbase;
    req->gs_base = task->thread.gsbase;

    put_task_struct(task);

    return 0;
}

// List threads in a process
static long list_process_threads(struct memreader_thread_list *list) {
    struct task_struct *task, *thread;
    int *kernel_tids;
    int count = 0;
    int max_threads;

    // Validate and cap max_threads to prevent huge allocations
    max_threads = list->max_threads;
    if (max_threads <= 0) {
        return -EINVAL;
    }
    if (max_threads > 4096) {
        max_threads = 4096;  // Cap at reasonable limit
    }

    task = get_task_by_pid(list->pid);
    if (!task) {
        return -ESRCH;
    }

    kernel_tids = kmalloc(max_threads * sizeof(int), GFP_KERNEL);
    if (!kernel_tids) {
        put_task_struct(task);
        return -ENOMEM;
    }

    // Iterate through all threads in the thread group
    rcu_read_lock();
    for_each_thread(task, thread) {
        if (count < max_threads) {
            kernel_tids[count] = thread->pid;
        }
        count++;
    }
    rcu_read_unlock();

    // Copy to user space
    list->num_threads = count;
    if (copy_to_user(list->tids, kernel_tids,
                     min(count, max_threads) * sizeof(int))) {
        kfree(kernel_tids);
        put_task_struct(task);
        return -EFAULT;
    }

    kfree(kernel_tids);
    put_task_struct(task);

    return 0;
}

// ============================================================================
// Page Decryption Monitor Implementation
// ============================================================================

// Read 16 bytes from a page for signature comparison
static bool read_page_signature(struct mm_struct *mm, unsigned long addr, uint8_t *sig) {
    unsigned long phys_addr;
    enum page_status status;

    phys_addr = virt_to_phys_manual(mm, addr, &status);
    if (phys_addr == 0 || status != PAGE_STATUS_OK) {
        return false;
    }

    return read_physical_memory(phys_addr, sig, 16);
}

// Check if signature indicates encrypted page (mostly 0xCC)
static bool is_encrypted_signature(uint8_t *sig) {
    int cc_count = 0;
    int i;
    for (i = 0; i < 16; i++) {
        if (sig[i] == 0xCC) cc_count++;
    }
    return cc_count >= 12;  // At least 12/16 bytes are 0xCC
}

// Capture all thread states for a process into a capture event
// Must be called WITHOUT monitor_mutex held (we acquire it internally)
static void capture_all_threads(int pid, unsigned long page_addr) {
    struct task_struct *task, *thread;
    struct pt_regs *regs;
    struct memreader_capture_event *event;
    int count = 0;
    int slot;

    task = get_task_by_pid(pid);
    if (!task) return;

    // Lock for ring buffer access
    mutex_lock(&monitor_mutex);

    if (!monitor_state.captures) {
        mutex_unlock(&monitor_mutex);
        put_task_struct(task);
        return;
    }

    // Get next slot in ring buffer
    slot = monitor_state.capture_head;
    monitor_state.capture_head = (monitor_state.capture_head + 1) % MAX_CAPTURES;
    if (monitor_state.capture_count < MAX_CAPTURES) {
        monitor_state.capture_count++;
    }

    event = &monitor_state.captures[slot];
    event->page_addr = page_addr;
    event->timestamp = jiffies;

    rcu_read_lock();
    for_each_thread(task, thread) {
        if (count >= MAX_CAPTURE_THREADS) break;

        regs = task_pt_regs(thread);
        if (regs) {
            event->threads[count].tid = thread->pid;
            event->threads[count].rip = regs->ip;
            event->threads[count].rsp = regs->sp;
            event->threads[count].rbp = regs->bp;
            event->threads[count].rax = regs->ax;
            memset(event->threads[count].stack, 0, sizeof(event->threads[count].stack));
        }
        count++;
    }
    rcu_read_unlock();

    event->num_threads = count;

    mutex_unlock(&monitor_mutex);
    put_task_struct(task);
}

// Monitor thread function - runs continuously until stopped
static int page_monitor_thread_fn(void *data) {
    struct task_struct *task;
    struct mm_struct *mm;
    uint8_t current_sig[16];
    int i;
    int pages_remaining;

    printk(KERN_INFO "MemReader: Page monitor thread started for PID %d, watching %d pages\n",
           monitor_state.pid, monitor_state.num_pages);

    while (!kthread_should_stop() && monitor_state.active) {
        task = get_task_by_pid(monitor_state.pid);
        if (!task) {
            printk(KERN_WARNING "MemReader: Target process %d no longer exists\n",
                   monitor_state.pid);
            break;
        }

        mm = get_task_mm(task);
        if (!mm) {
            put_task_struct(task);
            break;
        }

        mmap_read_lock(mm);

        pages_remaining = 0;

        // Check each watched page
        for (i = 0; i < monitor_state.num_pages; i++) {
            if (monitor_state.pages[i].changed) continue;  // Already detected

            pages_remaining++;

            if (!read_page_signature(mm, monitor_state.pages[i].address, current_sig)) {
                continue;  // Page not readable
            }

            // Compare signatures
            if (memcmp(current_sig, monitor_state.pages[i].signature, 16) != 0) {
                // Page content changed!
                // Check if it was encrypted before and now isn't
                if (is_encrypted_signature(monitor_state.pages[i].signature) &&
                    !is_encrypted_signature(current_sig)) {

                    // Mark as changed FIRST
                    monitor_state.pages[i].changed = 1;
                    monitor_state.pages_changed++;

                    // Release lock, capture threads, reacquire
                    mmap_read_unlock(mm);

                    // Capture all thread states immediately
                    capture_all_threads(monitor_state.pid, monitor_state.pages[i].address);

                    printk_ratelimited(KERN_INFO "MemReader: Page 0x%lx decrypted (%lu total)\n",
                           monitor_state.pages[i].address, monitor_state.pages_changed);

                    mmap_read_lock(mm);
                } else {
                    // Update signature for non-decrypt changes
                    memcpy(monitor_state.pages[i].signature, current_sig, 16);
                }
            }
        }

        mmap_read_unlock(mm);
        mmput(mm);
        put_task_struct(task);

        monitor_state.poll_count++;

        // Check if all pages have been decrypted
        if (pages_remaining == 0) {
            printk(KERN_INFO "MemReader: All watched pages decrypted, stopping\n");
            break;
        }

        // Sleep for poll interval
        usleep_range(monitor_state.poll_interval_us,
                     monitor_state.poll_interval_us + 100);
    }

    printk(KERN_INFO "MemReader: Page monitor thread exiting (polls=%lu, changed=%lu, captures=%d)\n",
           monitor_state.poll_count, monitor_state.pages_changed, monitor_state.capture_count);
    monitor_state.active = 0;
    return 0;
}

// Start page monitoring
static long start_page_monitor(struct memreader_page_monitor_config __user *user_config) {
    struct memreader_page_monitor_config config;
    unsigned long *user_pages = NULL;
    struct task_struct *task;
    struct mm_struct *mm;
    int i;

    if (copy_from_user(&config, user_config, sizeof(config))) {
        return -EFAULT;
    }

    mutex_lock(&monitor_mutex);

    if (monitor_state.active) {
        mutex_unlock(&monitor_mutex);
        return -EBUSY;
    }

    // Validate
    if (config.num_pages <= 0 || config.num_pages > MAX_WATCH_PAGES) {
        mutex_unlock(&monitor_mutex);
        return -EINVAL;
    }
    if (config.poll_interval_us < 100) {
        config.poll_interval_us = 100;  // Minimum 100us
    }

    // Allocate temp buffer for page addresses from userspace
    user_pages = kvzalloc(config.num_pages * sizeof(unsigned long), GFP_KERNEL);
    if (!user_pages) {
        mutex_unlock(&monitor_mutex);
        return -ENOMEM;
    }

    // Copy page addresses from userspace
    if (copy_from_user(user_pages, config.pages, config.num_pages * sizeof(unsigned long))) {
        kvfree(user_pages);
        mutex_unlock(&monitor_mutex);
        return -EFAULT;
    }

    // Find target process
    task = get_task_by_pid(config.pid);
    if (!task) {
        kvfree(user_pages);
        mutex_unlock(&monitor_mutex);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        kvfree(user_pages);
        mutex_unlock(&monitor_mutex);
        return -EINVAL;
    }

    // Allocate pages array
    monitor_state.pages = kvzalloc(config.num_pages * sizeof(struct page_watch_entry), GFP_KERNEL);
    if (!monitor_state.pages) {
        mmput(mm);
        put_task_struct(task);
        kvfree(user_pages);
        mutex_unlock(&monitor_mutex);
        return -ENOMEM;
    }

    // Allocate captures ring buffer
    monitor_state.captures = kvzalloc(MAX_CAPTURES * sizeof(struct memreader_capture_event), GFP_KERNEL);
    if (!monitor_state.captures) {
        kvfree(monitor_state.pages);
        monitor_state.pages = NULL;
        mmput(mm);
        put_task_struct(task);
        kvfree(user_pages);
        mutex_unlock(&monitor_mutex);
        return -ENOMEM;
    }

    // Initialize monitor state
    monitor_state.pid = config.pid;
    monitor_state.num_pages = config.num_pages;
    monitor_state.poll_interval_us = config.poll_interval_us;
    monitor_state.poll_count = 0;
    monitor_state.pages_changed = 0;
    monitor_state.capture_head = 0;
    monitor_state.capture_count = 0;

    mmap_read_lock(mm);

    for (i = 0; i < config.num_pages; i++) {
        monitor_state.pages[i].address = user_pages[i];
        monitor_state.pages[i].changed = 0;

        // Get initial signature
        if (!read_page_signature(mm, user_pages[i], monitor_state.pages[i].signature)) {
            memset(monitor_state.pages[i].signature, 0xCC, 16);  // Assume encrypted
        }
    }

    kvfree(user_pages);

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);

    // Start monitor thread
    monitor_state.active = 1;
    monitor_state.monitor_thread = kthread_run(page_monitor_thread_fn, NULL,
                                                "memreader_monitor");
    if (IS_ERR(monitor_state.monitor_thread)) {
        long err = PTR_ERR(monitor_state.monitor_thread);
        monitor_state.active = 0;
        monitor_state.monitor_thread = NULL;
        kvfree(monitor_state.captures);
        kvfree(monitor_state.pages);
        monitor_state.captures = NULL;
        monitor_state.pages = NULL;
        mutex_unlock(&monitor_mutex);
        return err;
    }

    mutex_unlock(&monitor_mutex);

    printk(KERN_INFO "MemReader: Started monitoring %d pages for PID %d\n",
           config.num_pages, config.pid);

    return 0;
}

// Stop page monitoring and free resources
static long stop_page_monitor(void) {
    mutex_lock(&monitor_mutex);

    if (monitor_state.active && monitor_state.monitor_thread) {
        monitor_state.active = 0;
        kthread_stop(monitor_state.monitor_thread);
        monitor_state.monitor_thread = NULL;
    }

    // Free allocated memory
    if (monitor_state.pages) {
        kvfree(monitor_state.pages);
        monitor_state.pages = NULL;
    }
    if (monitor_state.captures) {
        kvfree(monitor_state.captures);
        monitor_state.captures = NULL;
    }

    mutex_unlock(&monitor_mutex);
    return 0;
}

// Get capture results - returns all captures in ring buffer and clears it
static long get_decrypt_capture(struct memreader_decrypt_capture __user *user_capture) {
    struct memreader_decrypt_capture header;
    struct memreader_capture_event *captures_buf = NULL;
    int i, idx, copy_count;
    long ret = 0;

    // First, get the header to know how many captures to return
    if (copy_from_user(&header, user_capture, sizeof(header))) {
        return -EFAULT;
    }

    mutex_lock(&monitor_mutex);

    // Calculate how many to copy
    copy_count = min(monitor_state.capture_count, header.max_captures);
    copy_count = min(copy_count, MAX_CAPTURES);

    // Update header with current state
    header.num_captures = copy_count;
    header.total_pages_decrypted = monitor_state.pages_changed;
    header.still_monitoring = monitor_state.active ? 1 : 0;

    // Copy captures from ring buffer to userspace if any
    if (copy_count > 0 && monitor_state.captures && header.captures) {
        captures_buf = kvzalloc(copy_count * sizeof(struct memreader_capture_event), GFP_KERNEL);
        if (!captures_buf) {
            mutex_unlock(&monitor_mutex);
            return -ENOMEM;
        }

        for (i = 0; i < copy_count; i++) {
            // Read from oldest to newest
            idx = (monitor_state.capture_head - monitor_state.capture_count + i + MAX_CAPTURES) % MAX_CAPTURES;
            memcpy(&captures_buf[i], &monitor_state.captures[idx],
                   sizeof(struct memreader_capture_event));
        }

        // Clear the ring buffer after copying - prevents double-processing
        monitor_state.capture_head = 0;
        monitor_state.capture_count = 0;
    }

    mutex_unlock(&monitor_mutex);

    // Copy header back
    if (copy_to_user(user_capture, &header, sizeof(header))) {
        if (captures_buf) kvfree(captures_buf);
        return -EFAULT;
    }

    // Copy captures array to userspace
    if (captures_buf && header.captures) {
        if (copy_to_user(header.captures, captures_buf,
                         copy_count * sizeof(struct memreader_capture_event))) {
            ret = -EFAULT;
        }
        kvfree(captures_buf);
    }

    return ret;
}

// Get monitor status
static long get_monitor_status(struct memreader_monitor_status __user *user_status) {
    struct memreader_monitor_status status;

    mutex_lock(&monitor_mutex);

    status.active = monitor_state.active;
    status.pid = monitor_state.pid;
    status.num_pages_watching = monitor_state.num_pages;
    status.polls = monitor_state.poll_count;
    status.pages_changed = monitor_state.pages_changed;

    mutex_unlock(&monitor_mutex);

    if (copy_to_user(user_status, &status, sizeof(status))) {
        return -EFAULT;
    }

    return 0;
}

// ============================================================================
// Syscall Tracing Implementation
// ============================================================================

// Tracepoint callback: called on syscall entry
// Signature: void (*)(void *data, struct pt_regs *regs, long id)
static void syscall_trace_callback(void *__data, struct pt_regs *regs, long id) {
    struct task_struct *task = current;
    struct memreader_syscall_entry entry;
    unsigned long flags;

    // Check if tracing is active
    if (!syscall_state.active)
        return;

    // Filter by PID if specified
    if (syscall_state.target_pid != 0 && task->tgid != syscall_state.target_pid)
        return;

    // Skip if not tracing entries
    if (!syscall_state.trace_entries)
        return;

    // Fill entry
    entry.timestamp = jiffies;
    entry.pid = task->tgid;
    entry.tid = task->pid;
    entry.syscall_nr = id;  // Syscall number from tracepoint
    entry.arg0 = regs->di;
    entry.arg1 = regs->si;
    entry.arg2 = regs->dx;
    entry.arg3 = regs->r10;
    entry.arg4 = regs->r8;
    entry.arg5 = regs->r9;
    entry.ret = 0;
    entry.rip = regs->ip;
    entry.is_entry = 1;

    // Add to ring buffer
    spin_lock_irqsave(&syscall_lock, flags);

    syscall_state.total_syscalls++;

    if (syscall_state.count >= MAX_SYSCALL_TRACES) {
        // Buffer full - drop oldest entry
        syscall_state.tail = (syscall_state.tail + 1) % MAX_SYSCALL_TRACES;
        syscall_state.count--;
        syscall_state.dropped++;
        syscall_state.overflow = 1;
    }

    if (syscall_state.buffer) {
        syscall_state.buffer[syscall_state.head] = entry;
        syscall_state.head = (syscall_state.head + 1) % MAX_SYSCALL_TRACES;
        syscall_state.count++;
    }

    spin_unlock_irqrestore(&syscall_lock, flags);
}

// Start syscall tracing
static long start_syscall_trace(struct memreader_syscall_config __user *user_config) {
    struct memreader_syscall_config config;
    unsigned long flags;
    int ret;

    if (copy_from_user(&config, user_config, sizeof(config)))
        return -EFAULT;

    spin_lock_irqsave(&syscall_lock, flags);

    if (syscall_state.active) {
        spin_unlock_irqrestore(&syscall_lock, flags);
        return -EBUSY;
    }

    // Allocate buffer if not already
    if (!syscall_state.buffer) {
        spin_unlock_irqrestore(&syscall_lock, flags);
        syscall_state.buffer = kvzalloc(sizeof(struct memreader_syscall_entry) * MAX_SYSCALL_TRACES, GFP_KERNEL);
        if (!syscall_state.buffer)
            return -ENOMEM;
        spin_lock_irqsave(&syscall_lock, flags);
    }

    // Reset state
    syscall_state.head = 0;
    syscall_state.tail = 0;
    syscall_state.count = 0;
    syscall_state.overflow = 0;
    syscall_state.total_syscalls = 0;
    syscall_state.dropped = 0;

    syscall_state.target_pid = config.pid;
    syscall_state.trace_entries = config.trace_entries;
    syscall_state.trace_exits = config.trace_exits;

    spin_unlock_irqrestore(&syscall_lock, flags);

    // Find the sys_enter tracepoint using our kallsyms helper
    if (!tp_sys_enter) {
        unsigned long tp_addr = lookup_symbol("__tracepoint_sys_enter");
        if (!tp_addr) {
            printk(KERN_ERR "MemReader: Failed to find __tracepoint_sys_enter\n");
            printk(KERN_ERR "MemReader: Ensure CONFIG_TRACEPOINTS is enabled\n");
            return -ENOENT;
        }
        tp_sys_enter = (struct tracepoint *)tp_addr;
        printk(KERN_INFO "MemReader: Found __tracepoint_sys_enter at 0x%lx\n", tp_addr);
    }

    // Register our callback with the tracepoint
    ret = tracepoint_probe_register(tp_sys_enter, syscall_trace_callback, NULL);
    if (ret < 0) {
        printk(KERN_ERR "MemReader: Failed to register tracepoint probe: %d\n", ret);
        return ret;
    }

    syscall_state.active = 1;
    printk(KERN_INFO "MemReader: Syscall tracing started for PID %d (using tracepoint)\n", config.pid);

    return 0;
}

// Stop syscall tracing
static long stop_syscall_trace(void) {
    unsigned long flags;

    spin_lock_irqsave(&syscall_lock, flags);

    if (!syscall_state.active) {
        spin_unlock_irqrestore(&syscall_lock, flags);
        return 0;
    }

    syscall_state.active = 0;
    spin_unlock_irqrestore(&syscall_lock, flags);

    if (tp_sys_enter) {
        tracepoint_probe_unregister(tp_sys_enter, syscall_trace_callback, NULL);
        tracepoint_synchronize_unregister();  // Wait for all callbacks to finish
    }
    printk(KERN_INFO "MemReader: Syscall tracing stopped\n");

    return 0;
}

// Get syscall traces
static long get_syscall_traces(struct memreader_syscall_buffer __user *user_buf) {
    struct memreader_syscall_buffer buf;
    struct memreader_syscall_entry *entries;
    unsigned long flags;
    int to_copy, i;

    if (copy_from_user(&buf, user_buf, sizeof(buf)))
        return -EFAULT;

    if (buf.max_entries <= 0 || !buf.entries)
        return -EINVAL;

    // Allocate temporary kernel buffer
    entries = kvzalloc(sizeof(struct memreader_syscall_entry) * buf.max_entries, GFP_KERNEL);
    if (!entries)
        return -ENOMEM;

    spin_lock_irqsave(&syscall_lock, flags);

    to_copy = min(buf.max_entries, syscall_state.count);
    buf.overflow = syscall_state.overflow;

    for (i = 0; i < to_copy; i++) {
        int idx = (syscall_state.tail + i) % MAX_SYSCALL_TRACES;
        entries[i] = syscall_state.buffer[idx];
    }

    // Remove copied entries from ring buffer
    syscall_state.tail = (syscall_state.tail + to_copy) % MAX_SYSCALL_TRACES;
    syscall_state.count -= to_copy;

    // Clear overflow flag after read
    syscall_state.overflow = 0;

    spin_unlock_irqrestore(&syscall_lock, flags);

    buf.num_entries = to_copy;

    // Copy to userspace
    if (copy_to_user(buf.entries, entries, sizeof(struct memreader_syscall_entry) * to_copy)) {
        kvfree(entries);
        return -EFAULT;
    }

    if (copy_to_user(user_buf, &buf, sizeof(buf))) {
        kvfree(entries);
        return -EFAULT;
    }

    kvfree(entries);
    return to_copy;
}

// Get syscall trace status
static long get_syscall_status(struct memreader_syscall_status __user *user_status) {
    struct memreader_syscall_status status;
    unsigned long flags;

    spin_lock_irqsave(&syscall_lock, flags);

    status.active = syscall_state.active;
    status.pid = syscall_state.target_pid;
    status.total_syscalls = syscall_state.total_syscalls;
    status.dropped = syscall_state.dropped;

    spin_unlock_irqrestore(&syscall_lock, flags);

    if (copy_to_user(user_status, &status, sizeof(status)))
        return -EFAULT;

    return 0;
}

// Clear syscall traces
static long clear_syscall_traces(void) {
    unsigned long flags;

    spin_lock_irqsave(&syscall_lock, flags);

    syscall_state.head = 0;
    syscall_state.tail = 0;
    syscall_state.count = 0;
    syscall_state.overflow = 0;

    spin_unlock_irqrestore(&syscall_lock, flags);

    return 0;
}

// ============================================================================
// Uprobe Implementation
// ============================================================================

// Uprobe handler - called when any thread hits the probed address
static int uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs, __u64 *data)
{
    struct active_uprobe *up;
    unsigned long flags;
    int slot;
    int i;

    // Find which uprobe this consumer belongs to
    spin_lock_irqsave(&uprobe_lock, flags);

    up = NULL;
    for (i = 0; i < MAX_UPROBES; i++) {
        if (uprobes[i].active && &uprobes[i].consumer == uc) {
            up = &uprobes[i];
            break;
        }
    }

    if (!up || !up->hits) {
        spin_unlock_irqrestore(&uprobe_lock, flags);
        return 0;
    }

    // Filter by PID (tgid)
    if (up->pid != 0 && current->tgid != up->pid) {
        spin_unlock_irqrestore(&uprobe_lock, flags);
        return 0;
    }

    up->total_hits++;

    // Store hit in ring buffer
    slot = up->head;
    up->head = (up->head + 1) % MAX_UPROBE_HITS;
    if (up->count >= MAX_UPROBE_HITS) {
        up->overflow = 1;
    } else {
        up->count++;
    }

    up->hits[slot].timestamp = jiffies;
    up->hits[slot].tid = current->pid;
    up->hits[slot].rip = regs->ip;
    up->hits[slot].rax = regs->ax;
    up->hits[slot].rbx = regs->bx;
    up->hits[slot].rcx = regs->cx;
    up->hits[slot].rdx = regs->dx;
    up->hits[slot].rsi = regs->si;
    up->hits[slot].rdi = regs->di;
    up->hits[slot].rbp = regs->bp;
    up->hits[slot].rsp = regs->sp;
    up->hits[slot].r8 = regs->r8;
    up->hits[slot].r9 = regs->r9;
    up->hits[slot].r10 = regs->r10;
    up->hits[slot].r11 = regs->r11;
    up->hits[slot].r12 = regs->r12;
    up->hits[slot].r13 = regs->r13;
    up->hits[slot].r14 = regs->r14;
    up->hits[slot].r15 = regs->r15;

    spin_unlock_irqrestore(&uprobe_lock, flags);

    printk_ratelimited(KERN_INFO "MemReader: Uprobe hit! TID=%d RIP=0x%lx RBX=0x%lx\n",
                       current->pid, regs->ip, regs->bx);

    return 0;  // Continue execution
}

// Find inode and file offset for a virtual address in a process
static int find_uprobe_target(int pid, unsigned long vaddr,
                               struct inode **out_inode, unsigned long *out_offset)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct inode *inode = NULL;
    unsigned long offset = 0;
    int ret = -ENOENT;

    task = get_task_by_pid(pid);
    if (!task) {
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    mmap_read_lock(mm);

    // Find VMA containing the address
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vma = vma_lookup(mm, vaddr);
#else
    vma = find_vma(mm, vaddr);
    if (vma && vma->vm_start > vaddr)
        vma = NULL;
#endif

    if (!vma) {
        printk(KERN_WARNING "MemReader: No VMA found for address 0x%lx\n", vaddr);
        goto out;
    }

    // Check if it's file-backed
    if (!vma->vm_file) {
        printk(KERN_WARNING "MemReader: VMA at 0x%lx is not file-backed\n", vaddr);
        ret = -ENOENT;
        goto out;
    }

    inode = vma->vm_file->f_inode;
    if (!inode) {
        printk(KERN_WARNING "MemReader: No inode for VMA at 0x%lx\n", vaddr);
        ret = -ENOENT;
        goto out;
    }

    // Calculate file offset
    // offset = (vaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT)
    offset = (vaddr - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);

    printk(KERN_INFO "MemReader: Found uprobe target: vaddr=0x%lx vma_start=0x%lx "
           "vm_pgoff=0x%lx -> file_offset=0x%lx inode=%p\n",
           vaddr, vma->vm_start, vma->vm_pgoff, offset, inode);

    // Get reference to inode
    ihold(inode);
    *out_inode = inode;
    *out_offset = offset;
    ret = 0;

out:
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

// Set uprobe at address
static long set_uprobe(struct memreader_uprobe_request *req)
{
    struct active_uprobe *up;
    unsigned long flags;
    struct inode *inode;
    unsigned long file_offset;
    struct uprobe *uprobe_ptr;
    int probe_id = req->probe_id;
    int ret;

    // Input validation
    if (probe_id < 0 || probe_id >= MAX_UPROBES) {
        return -EINVAL;
    }
    if (req->pid <= 0) {
        return -EINVAL;
    }
    if (req->address == 0) {
        return -EINVAL;
    }

    // Check if probe slot is available
    spin_lock_irqsave(&uprobe_lock, flags);
    if (uprobes[probe_id].active) {
        spin_unlock_irqrestore(&uprobe_lock, flags);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&uprobe_lock, flags);

    // Find inode and file offset
    ret = find_uprobe_target(req->pid, req->address, &inode, &file_offset);
    if (ret < 0) {
        printk(KERN_ERR "MemReader: Failed to find uprobe target: %d\n", ret);
        return ret;
    }

    up = &uprobes[probe_id];

    // Allocate hit buffer
    up->hits = kvzalloc(MAX_UPROBE_HITS * sizeof(struct uprobe_hit_record), GFP_KERNEL);
    if (!up->hits) {
        iput(inode);
        return -ENOMEM;
    }

    // Initialize uprobe consumer
    memset(&up->consumer, 0, sizeof(up->consumer));
    up->consumer.handler = uprobe_handler;

    // Register the uprobe (new API: inode, offset, ref_ctr_offset, consumer)
    // ref_ctr_offset=0 means no semaphore/reference counter
    uprobe_ptr = uprobe_register(inode, file_offset, 0, &up->consumer);
    if (IS_ERR(uprobe_ptr)) {
        ret = PTR_ERR(uprobe_ptr);
        printk(KERN_ERR "MemReader: uprobe_register failed: %d (inode=%p offset=0x%lx)\n",
               ret, inode, file_offset);
        kvfree(up->hits);
        up->hits = NULL;
        iput(inode);
        return ret;
    }

    // Store state
    spin_lock_irqsave(&uprobe_lock, flags);
    up->active = 1;
    up->pid = req->pid;
    up->address = req->address;
    up->file_offset = file_offset;
    up->inode = inode;
    up->uprobe = uprobe_ptr;
    up->head = 0;
    up->count = 0;
    up->overflow = 0;
    up->total_hits = 0;
    spin_unlock_irqrestore(&uprobe_lock, flags);

    printk(KERN_INFO "MemReader: Uprobe %d set at 0x%lx (file offset 0x%lx) for PID %d\n",
           probe_id, req->address, file_offset, req->pid);

    return 0;
}

// Clear uprobe
static long clear_uprobe(struct memreader_uprobe_request *req)
{
    struct active_uprobe *up;
    unsigned long flags;
    int probe_id = req->probe_id;
    struct inode *inode;
    struct uprobe *uprobe_ptr;

    if (probe_id < 0 || probe_id >= MAX_UPROBES) {
        return -EINVAL;
    }

    spin_lock_irqsave(&uprobe_lock, flags);

    up = &uprobes[probe_id];
    if (!up->active) {
        spin_unlock_irqrestore(&uprobe_lock, flags);
        return -ENOENT;
    }

    // Save info needed for unregistration
    inode = up->inode;
    uprobe_ptr = up->uprobe;
    up->active = 0;

    spin_unlock_irqrestore(&uprobe_lock, flags);

    // Unregister uprobe (outside spinlock) - new API
    uprobe_unregister_nosync(uprobe_ptr, &up->consumer);
    uprobe_unregister_sync();

    // Release inode reference
    iput(inode);

    // Free hit buffer
    if (up->hits) {
        kvfree(up->hits);
        up->hits = NULL;
    }

    up->inode = NULL;
    up->uprobe = NULL;

    printk(KERN_INFO "MemReader: Uprobe %d cleared\n", probe_id);

    return 0;
}

// Get uprobe hits
static long get_uprobe_hits(struct memreader_uprobe_hits __user *user_hits)
{
    struct memreader_uprobe_hits req;
    struct active_uprobe *up;
    struct memreader_uprobe_hit *hits_buf = NULL;
    unsigned long flags;
    int probe_id;
    int to_copy, i, idx;
    long ret = 0;

    if (copy_from_user(&req, user_hits, sizeof(req))) {
        return -EFAULT;
    }

    probe_id = req.probe_id;
    if (probe_id < 0 || probe_id >= MAX_UPROBES) {
        return -EINVAL;
    }

    if (req.max_hits <= 0 || !req.hits) {
        return -EINVAL;
    }

    // Allocate temp buffer
    hits_buf = kvzalloc(req.max_hits * sizeof(struct memreader_uprobe_hit), GFP_KERNEL);
    if (!hits_buf) {
        return -ENOMEM;
    }

    spin_lock_irqsave(&uprobe_lock, flags);

    up = &uprobes[probe_id];
    if (!up->active || !up->hits) {
        spin_unlock_irqrestore(&uprobe_lock, flags);
        kvfree(hits_buf);
        req.num_hits = 0;
        req.total_hits = 0;
        req.overflow = 0;
        if (copy_to_user(user_hits, &req, sizeof(req))) {
            return -EFAULT;
        }
        return 0;
    }

    // Copy hits from ring buffer
    to_copy = min(req.max_hits, up->count);
    req.total_hits = up->total_hits;
    req.overflow = up->overflow;

    for (i = 0; i < to_copy; i++) {
        // Read from oldest to newest
        idx = (up->head - up->count + i + MAX_UPROBE_HITS) % MAX_UPROBE_HITS;

        hits_buf[i].timestamp = up->hits[idx].timestamp;
        hits_buf[i].tid = up->hits[idx].tid;
        hits_buf[i].rip = up->hits[idx].rip;
        hits_buf[i].rax = up->hits[idx].rax;
        hits_buf[i].rbx = up->hits[idx].rbx;
        hits_buf[i].rcx = up->hits[idx].rcx;
        hits_buf[i].rdx = up->hits[idx].rdx;
        hits_buf[i].rsi = up->hits[idx].rsi;
        hits_buf[i].rdi = up->hits[idx].rdi;
        hits_buf[i].rbp = up->hits[idx].rbp;
        hits_buf[i].rsp = up->hits[idx].rsp;
        hits_buf[i].r8 = up->hits[idx].r8;
        hits_buf[i].r9 = up->hits[idx].r9;
        hits_buf[i].r10 = up->hits[idx].r10;
        hits_buf[i].r11 = up->hits[idx].r11;
        hits_buf[i].r12 = up->hits[idx].r12;
        hits_buf[i].r13 = up->hits[idx].r13;
        hits_buf[i].r14 = up->hits[idx].r14;
        hits_buf[i].r15 = up->hits[idx].r15;
    }

    req.num_hits = to_copy;

    // Clear ring buffer after reading
    up->head = 0;
    up->count = 0;
    up->overflow = 0;

    spin_unlock_irqrestore(&uprobe_lock, flags);

    // Copy to userspace
    if (copy_to_user(req.hits, hits_buf, to_copy * sizeof(struct memreader_uprobe_hit))) {
        ret = -EFAULT;
    }

    if (copy_to_user(user_hits, &req, sizeof(req))) {
        ret = -EFAULT;
    }

    kvfree(hits_buf);
    return ret;
}

// Get uprobe status
static long get_uprobe_status(struct memreader_uprobe_status __user *user_status)
{
    struct memreader_uprobe_status status;
    struct active_uprobe *up;
    unsigned long flags;
    int probe_id;

    if (copy_from_user(&status, user_status, sizeof(status))) {
        return -EFAULT;
    }

    probe_id = status.probe_id;
    if (probe_id < 0 || probe_id >= MAX_UPROBES) {
        return -EINVAL;
    }

    spin_lock_irqsave(&uprobe_lock, flags);

    up = &uprobes[probe_id];
    status.active = up->active;
    status.pid = up->pid;
    status.address = up->address;
    status.total_hits = up->total_hits;
    status.file_offset = up->file_offset;

    spin_unlock_irqrestore(&uprobe_lock, flags);

    if (copy_to_user(user_status, &status, sizeof(status))) {
        return -EFAULT;
    }

    return 0;
}

// Clear uprobe hits (without removing the probe)
static long clear_uprobe_hits(struct memreader_uprobe_request *req)
{
    struct active_uprobe *up;
    unsigned long flags;
    int probe_id = req->probe_id;

    if (probe_id < 0 || probe_id >= MAX_UPROBES) {
        return -EINVAL;
    }

    spin_lock_irqsave(&uprobe_lock, flags);

    up = &uprobes[probe_id];
    if (up->active) {
        up->head = 0;
        up->count = 0;
        up->overflow = 0;
    }

    spin_unlock_irqrestore(&uprobe_lock, flags);

    return 0;
}

// ============================================================================
// Decrypt Hook Implementation (Hardware Breakpoint for JIT/Anonymous Memory)
// ============================================================================

// Decrypt hook breakpoint handler - captures full register state
static void decrypt_hook_handler(struct perf_event *bp, struct perf_sample_data *data,
                                  struct pt_regs *regs)
{
    unsigned long flags;
    int slot;

    if (!decrypt_hook.active)
        return;

    // Filter by PID
    if (current->tgid != decrypt_hook.pid)
        return;

    // Filter by TID if specified
    if (decrypt_hook.tid != 0 && current->pid != decrypt_hook.tid)
        return;

    spin_lock_irqsave(&decrypt_hook_lock, flags);

    if (!decrypt_hook.entries) {
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);
        return;
    }

    decrypt_hook.total_captures++;

    // Store in ring buffer
    slot = decrypt_hook.head;
    decrypt_hook.head = (decrypt_hook.head + 1) % MAX_DECRYPT_CAPTURES;
    if (decrypt_hook.count >= MAX_DECRYPT_CAPTURES) {
        decrypt_hook.overflow = 1;
    } else {
        decrypt_hook.count++;
    }

    decrypt_hook.entries[slot].timestamp = jiffies;
    decrypt_hook.entries[slot].tid = current->pid;
    decrypt_hook.entries[slot].rip = regs->ip;
    decrypt_hook.entries[slot].decrypted = regs->ax;   // RAX = decrypted pointer
    decrypt_hook.entries[slot].encrypted = regs->bx;   // RBX was used in computation
    decrypt_hook.entries[slot].rcx = regs->cx;
    decrypt_hook.entries[slot].rdx = regs->dx;
    decrypt_hook.entries[slot].r8 = regs->r8;          // R8 = XOR key in Theia
    decrypt_hook.entries[slot].r11 = regs->r11;        // R11 = decrypted target in Theia

    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    printk_ratelimited(KERN_INFO "MemReader: Decrypt hook hit! TID=%d RAX=0x%lx RBX=0x%lx R11=0x%lx\n",
                       current->pid, regs->ax, regs->bx, regs->r11);
}

// Set decrypt hook at address - registers breakpoints on ALL threads
static long set_decrypt_hook(struct memreader_decrypt_hook_config *config)
{
    struct perf_event_attr attr;
    struct task_struct *leader, *thread;
    struct perf_event *bp_event;
    unsigned long flags;
    int num_bps = 0;

    // Input validation
    if (config->pid <= 0) {
        return -EINVAL;
    }
    if (config->address == 0) {
        return -EINVAL;
    }
    // tid can be 0 (meaning all threads) or positive
    if (config->tid < 0) {
        return -EINVAL;
    }

    // Check if already active
    spin_lock_irqsave(&decrypt_hook_lock, flags);
    if (decrypt_hook.active) {
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    // Find target process (thread group leader)
    leader = get_task_by_pid(config->pid);
    if (!leader) {
        return -ESRCH;
    }

    // Allocate capture buffer
    decrypt_hook.entries = kvzalloc(MAX_DECRYPT_CAPTURES * sizeof(struct memreader_decrypt_entry), GFP_KERNEL);
    if (!decrypt_hook.entries) {
        put_task_struct(leader);
        return -ENOMEM;
    }

    // Initialize state
    memset(decrypt_hook.bp_events, 0, sizeof(decrypt_hook.bp_events));
    memset(decrypt_hook.bp_tids, 0, sizeof(decrypt_hook.bp_tids));
    decrypt_hook.num_breakpoints = 0;

    // Initialize perf event attributes for execution breakpoint
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.pinned = 1;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = config->address;
    attr.bp_len = sizeof(long);

    // Iterate through ALL threads in the process
    rcu_read_lock();
    for_each_thread(leader, thread) {
        if (num_bps >= MAX_THREAD_BREAKPOINTS) {
            printk(KERN_WARNING "MemReader: Hit max thread limit (%d), some threads not hooked\n",
                   MAX_THREAD_BREAKPOINTS);
            break;
        }

        // Skip threads that are exiting - they won't execute user code anymore
        // Check this while still under RCU protection
        if (thread->flags & PF_EXITING) {
            continue;
        }

        // Get a reference to this thread before dropping RCU lock
        // This prevents the task_struct from being freed, but the thread
        // could still start exiting after we drop RCU
        get_task_struct(thread);
        rcu_read_unlock();

        // Double-check exiting flag after acquiring reference
        // This narrows the race window (though doesn't eliminate it entirely -
        // register_user_hw_breakpoint handles the remaining edge cases)
        if (thread->flags & PF_EXITING) {
            put_task_struct(thread);
            rcu_read_lock();
            continue;
        }

        // Register breakpoint for this thread
        bp_event = register_user_hw_breakpoint(&attr, decrypt_hook_handler, NULL, thread);
        if (IS_ERR(bp_event)) {
            // Some threads may fail (e.g., kernel threads, exiting threads) - that's okay
            printk_ratelimited(KERN_DEBUG "MemReader: Failed to set bp on TID %d: %ld\n",
                               thread->pid, PTR_ERR(bp_event));
            put_task_struct(thread);
            rcu_read_lock();
            continue;
        }

        decrypt_hook.bp_events[num_bps] = bp_event;
        decrypt_hook.bp_tids[num_bps] = thread->pid;
        num_bps++;

        put_task_struct(thread);
        rcu_read_lock();
    }
    rcu_read_unlock();

    put_task_struct(leader);

    if (num_bps == 0) {
        printk(KERN_ERR "MemReader: Failed to set any breakpoints!\n");
        kvfree(decrypt_hook.entries);
        decrypt_hook.entries = NULL;
        return -EINVAL;
    }

    // Store state
    spin_lock_irqsave(&decrypt_hook_lock, flags);
    decrypt_hook.active = 1;
    decrypt_hook.pid = config->pid;
    decrypt_hook.tid = config->tid;
    decrypt_hook.address = config->address;
    decrypt_hook.num_breakpoints = num_bps;
    decrypt_hook.head = 0;
    decrypt_hook.count = 0;
    decrypt_hook.overflow = 0;
    decrypt_hook.total_captures = 0;
    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    printk(KERN_INFO "MemReader: Decrypt hook set at 0x%lx for PID %d - %d thread breakpoints active\n",
           config->address, config->pid, num_bps);

    return 0;
}

// Update decrypt hook - add breakpoints to any new threads
static long update_decrypt_hook(void)
{
    struct perf_event_attr attr;
    struct task_struct *leader, *thread;
    struct perf_event *bp_event;
    unsigned long flags;
    int new_bps = 0;
    int i;

    spin_lock_irqsave(&decrypt_hook_lock, flags);
    if (!decrypt_hook.active) {
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);
        return -EINVAL;
    }
    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    // Find target process
    leader = get_task_by_pid(decrypt_hook.pid);
    if (!leader) {
        return -ESRCH;
    }

    // Initialize perf event attributes
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.pinned = 1;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = decrypt_hook.address;
    attr.bp_len = sizeof(long);

    // Iterate through all threads, add breakpoints to new ones
    rcu_read_lock();
    for_each_thread(leader, thread) {
        int already_hooked = 0;

        // Check if this thread already has a breakpoint
        spin_lock_irqsave(&decrypt_hook_lock, flags);
        for (i = 0; i < decrypt_hook.num_breakpoints; i++) {
            if (decrypt_hook.bp_tids[i] == thread->pid) {
                already_hooked = 1;
                break;
            }
        }
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);

        if (already_hooked) continue;

        // Skip exiting threads - check while under RCU protection
        if (thread->flags & PF_EXITING) continue;

        // Check if we have room for more breakpoints
        spin_lock_irqsave(&decrypt_hook_lock, flags);
        if (decrypt_hook.num_breakpoints >= MAX_THREAD_BREAKPOINTS) {
            spin_unlock_irqrestore(&decrypt_hook_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);

        // New thread - add breakpoint
        get_task_struct(thread);
        rcu_read_unlock();

        // Double-check exiting flag after acquiring reference
        if (thread->flags & PF_EXITING) {
            put_task_struct(thread);
            rcu_read_lock();
            continue;
        }

        bp_event = register_user_hw_breakpoint(&attr, decrypt_hook_handler, NULL, thread);
        if (!IS_ERR(bp_event)) {
            spin_lock_irqsave(&decrypt_hook_lock, flags);
            decrypt_hook.bp_events[decrypt_hook.num_breakpoints] = bp_event;
            decrypt_hook.bp_tids[decrypt_hook.num_breakpoints] = thread->pid;
            decrypt_hook.num_breakpoints++;
            spin_unlock_irqrestore(&decrypt_hook_lock, flags);
            new_bps++;
        }

        put_task_struct(thread);
        rcu_read_lock();
    }
    rcu_read_unlock();

    put_task_struct(leader);

    if (new_bps > 0) {
        printk(KERN_INFO "MemReader: Added %d new thread breakpoints (total: %d)\n",
               new_bps, decrypt_hook.num_breakpoints);
    }

    return new_bps;
}

// Clear decrypt hook
static long clear_decrypt_hook(void)
{
    unsigned long flags;
    struct perf_event *bp_event;
    int num_bps, i;
    unsigned long total_caps;

    spin_lock_irqsave(&decrypt_hook_lock, flags);

    if (!decrypt_hook.active) {
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);
        return 0;
    }

    decrypt_hook.active = 0;
    num_bps = decrypt_hook.num_breakpoints;
    total_caps = decrypt_hook.total_captures;

    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    // Unregister all breakpoints (safe to do outside spinlock since we marked inactive)
    for (i = 0; i < num_bps; i++) {
        bp_event = decrypt_hook.bp_events[i];
        if (bp_event) {
            unregister_hw_breakpoint(bp_event);
            decrypt_hook.bp_events[i] = NULL;
        }
    }
    decrypt_hook.num_breakpoints = 0;

    // Free buffer
    if (decrypt_hook.entries) {
        kvfree(decrypt_hook.entries);
        decrypt_hook.entries = NULL;
    }

    printk(KERN_INFO "MemReader: Decrypt hook cleared - %d breakpoints removed (total captures: %lu)\n",
           num_bps, total_caps);

    return 0;
}

// Get decrypt captures
static long get_decrypt_entries(struct memreader_decrypt_hook_buffer __user *user_buf)
{
    struct memreader_decrypt_hook_buffer buf;
    struct memreader_decrypt_entry *entries_copy = NULL;
    unsigned long flags;
    int to_copy, i, idx;
    long ret = 0;

    if (copy_from_user(&buf, user_buf, sizeof(buf))) {
        return -EFAULT;
    }

    if (buf.max_entries <= 0 || !buf.entries) {
        return -EINVAL;
    }

    // Allocate temp buffer
    entries_copy = kvzalloc(buf.max_entries * sizeof(struct memreader_decrypt_entry), GFP_KERNEL);
    if (!entries_copy) {
        return -ENOMEM;
    }

    spin_lock_irqsave(&decrypt_hook_lock, flags);

    buf.active = decrypt_hook.active;
    buf.total_captures = decrypt_hook.total_captures;
    buf.overflow = decrypt_hook.overflow;

    if (!decrypt_hook.entries || decrypt_hook.count == 0) {
        buf.num_entries = 0;
        spin_unlock_irqrestore(&decrypt_hook_lock, flags);
        goto copy_out;
    }

    // Copy from ring buffer (oldest to newest)
    to_copy = min(buf.max_entries, decrypt_hook.count);
    for (i = 0; i < to_copy; i++) {
        idx = (decrypt_hook.head - decrypt_hook.count + i + MAX_DECRYPT_CAPTURES) % MAX_DECRYPT_CAPTURES;
        entries_copy[i] = decrypt_hook.entries[idx];
    }

    buf.num_entries = to_copy;

    // Clear ring buffer after reading
    decrypt_hook.head = 0;
    decrypt_hook.count = 0;
    decrypt_hook.overflow = 0;

    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

copy_out:
    // Copy to userspace
    if (buf.num_entries > 0) {
        if (copy_to_user(buf.entries, entries_copy,
                         buf.num_entries * sizeof(struct memreader_decrypt_entry))) {
            ret = -EFAULT;
        }
    }

    if (copy_to_user(user_buf, &buf, sizeof(buf))) {
        ret = -EFAULT;
    }

    kvfree(entries_copy);
    return ret;
}

// Clear decrypt entries without removing hook
static long clear_decrypt_entries(void)
{
    unsigned long flags;

    spin_lock_irqsave(&decrypt_hook_lock, flags);

    if (decrypt_hook.active) {
        decrypt_hook.head = 0;
        decrypt_hook.count = 0;
        decrypt_hook.overflow = 0;
    }

    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    return 0;
}

// Get decrypt hook status
static long get_decrypt_hook_status(struct memreader_decrypt_hook_status __user *user_status)
{
    struct memreader_decrypt_hook_status status;
    unsigned long flags;

    spin_lock_irqsave(&decrypt_hook_lock, flags);

    status.active = decrypt_hook.active;
    status.pid = decrypt_hook.pid;
    status.address = decrypt_hook.address;
    status.total_captures = decrypt_hook.total_captures;
    status.unique_pointers = 0;  // TODO: could track unique values if needed

    spin_unlock_irqrestore(&decrypt_hook_lock, flags);

    if (copy_to_user(user_status, &status, sizeof(status))) {
        return -EFAULT;
    }

    return 0;
}

// ============================================================================
// IOCTL Handler
// ============================================================================

static long memreader_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    long ret = 0;

    switch (cmd) {
        case MEMREADER_READ_MEMORY: {
            struct memreader_read_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = read_process_memory(req.pid, req.address, req.buffer, req.size);
            break;
        }

        case MEMREADER_GET_BASE: {
            struct memreader_base_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = get_process_base(req.pid, &req.base_address);
            if (ret == 0) {
                if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                    return -EFAULT;
                }
            }
            break;
        }

        case MEMREADER_SET_HWBP: {
            struct memreader_hwbp_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = set_hardware_breakpoint(&req);
            break;
        }

        case MEMREADER_CLEAR_HWBP: {
            struct memreader_hwbp_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = clear_hardware_breakpoint(&req);
            break;
        }

        case MEMREADER_GET_BP_HIT: {
            struct memreader_bp_hit_info info;
            if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
                return -EFAULT;
            }
            ret = get_breakpoint_hit(&info);
            if (ret == 0) {
                if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
                    return -EFAULT;
                }
            }
            break;
        }

        case MEMREADER_CLEAR_BP_HIT: {
            struct memreader_bp_hit_info info;
            if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
                return -EFAULT;
            }
            ret = clear_breakpoint_hit(&info);
            break;
        }

        case MEMREADER_READ_REGS: {
            struct memreader_regs_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = read_thread_registers(&req);
            if (ret == 0) {
                if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                    return -EFAULT;
                }
            }
            break;
        }

        case MEMREADER_LIST_THREADS: {
            struct memreader_thread_list list;
            if (copy_from_user(&list, (void __user *)arg, sizeof(list))) {
                return -EFAULT;
            }
            ret = list_process_threads(&list);
            if (ret == 0) {
                if (copy_to_user((void __user *)arg, &list, sizeof(list))) {
                    return -EFAULT;
                }
            }
            break;
        }

        // Page monitor operations
        case MEMREADER_START_PAGE_MONITOR:
            ret = start_page_monitor((struct memreader_page_monitor_config __user *)arg);
            break;

        case MEMREADER_STOP_PAGE_MONITOR:
            ret = stop_page_monitor();
            break;

        case MEMREADER_GET_DECRYPT_CAPTURE:
            ret = get_decrypt_capture((struct memreader_decrypt_capture __user *)arg);
            break;

        case MEMREADER_GET_MONITOR_STATUS:
            ret = get_monitor_status((struct memreader_monitor_status __user *)arg);
            break;

        // Syscall tracing operations
        case MEMREADER_START_SYSCALL_TRACE:
            ret = start_syscall_trace((struct memreader_syscall_config __user *)arg);
            break;

        case MEMREADER_STOP_SYSCALL_TRACE:
            ret = stop_syscall_trace();
            break;

        case MEMREADER_GET_SYSCALL_TRACES:
            ret = get_syscall_traces((struct memreader_syscall_buffer __user *)arg);
            break;

        case MEMREADER_GET_SYSCALL_STATUS:
            ret = get_syscall_status((struct memreader_syscall_status __user *)arg);
            break;

        case MEMREADER_CLEAR_SYSCALL_TRACES:
            ret = clear_syscall_traces();
            break;

        // Uprobe operations
        case MEMREADER_SET_UPROBE: {
            struct memreader_uprobe_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = set_uprobe(&req);
            break;
        }

        case MEMREADER_CLEAR_UPROBE: {
            struct memreader_uprobe_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = clear_uprobe(&req);
            break;
        }

        case MEMREADER_GET_UPROBE_HITS:
            ret = get_uprobe_hits((struct memreader_uprobe_hits __user *)arg);
            break;

        case MEMREADER_GET_UPROBE_STATUS:
            ret = get_uprobe_status((struct memreader_uprobe_status __user *)arg);
            break;

        case MEMREADER_CLEAR_UPROBE_HITS: {
            struct memreader_uprobe_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }
            ret = clear_uprobe_hits(&req);
            break;
        }

        // Decrypt hook operations
        case MEMREADER_SET_DECRYPT_HOOK: {
            struct memreader_decrypt_hook_config config;
            if (copy_from_user(&config, (void __user *)arg, sizeof(config))) {
                return -EFAULT;
            }
            ret = set_decrypt_hook(&config);
            break;
        }

        case MEMREADER_CLEAR_DECRYPT_HOOK:
            ret = clear_decrypt_hook();
            break;

        case MEMREADER_GET_DECRYPT_ENTRIES:
            ret = get_decrypt_entries((struct memreader_decrypt_hook_buffer __user *)arg);
            break;

        case MEMREADER_CLEAR_DECRYPT_ENTRIES:
            ret = clear_decrypt_entries();
            break;

        case MEMREADER_GET_DECRYPT_HOOK_STATUS:
            ret = get_decrypt_hook_status((struct memreader_decrypt_hook_status __user *)arg);
            break;

        case MEMREADER_UPDATE_DECRYPT_HOOK:
            ret = update_decrypt_hook();
            break;

        default:
            ret = -EINVAL;
    }

    return ret;
}

// File operations
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = memreader_ioctl,
};

// ============================================================================
// Module Init/Exit
// ============================================================================

static int __init memreader_init(void) {
    int i;

    printk(KERN_INFO "MemReader: Initializing module v2.4 (with decrypt hook support)\n");

    // Initialize breakpoint state
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        breakpoints[i].active = 0;
        breakpoints[i].bp_event = NULL;
    }

    for (i = 0; i < MAX_HIT_RECORDS; i++) {
        hit_records[i].valid = 0;
    }

    // Initialize page monitor state
    memset(&monitor_state, 0, sizeof(monitor_state));

    // Initialize syscall tracing state
    memset(&syscall_state, 0, sizeof(syscall_state));

    // Initialize uprobe state
    for (i = 0; i < MAX_UPROBES; i++) {
        uprobes[i].active = 0;
        uprobes[i].hits = NULL;
        uprobes[i].inode = NULL;
        uprobes[i].uprobe = NULL;
    }

    // Initialize decrypt hook state
    memset(&decrypt_hook, 0, sizeof(decrypt_hook));

    // Look up access_remote_vm for shared mapping support (Wine/Proton tmpmap)
    fn_access_remote_vm = (access_remote_vm_t)lookup_symbol("access_remote_vm");
    if (fn_access_remote_vm) {
        printk(KERN_INFO "MemReader: Found access_remote_vm at 0x%px (shared mapping support enabled)\n",
               fn_access_remote_vm);
    } else {
        printk(KERN_WARNING "MemReader: access_remote_vm not found, falling back to page table walking\n");
    }

    // Register character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "MemReader: Failed to register major number\n");
        return major_number;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    memreader_class = class_create(CLASS_NAME);
#else
    memreader_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(memreader_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "MemReader: Failed to register device class\n");
        return PTR_ERR(memreader_class);
    }

    memreader_device = device_create(memreader_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(memreader_device)) {
        class_destroy(memreader_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "MemReader: Failed to create device\n");
        return PTR_ERR(memreader_device);
    }

    printk(KERN_INFO "MemReader: Device created successfully\n");
    return 0;
}

static void __exit memreader_exit(void) {
    int i;

    // Clean up decrypt hook if active
    if (decrypt_hook.active) {
        for (i = 0; i < decrypt_hook.num_breakpoints; i++) {
            if (decrypt_hook.bp_events[i]) {
                unregister_hw_breakpoint(decrypt_hook.bp_events[i]);
                decrypt_hook.bp_events[i] = NULL;
            }
        }
        decrypt_hook.num_breakpoints = 0;
        decrypt_hook.active = 0;
    }
    if (decrypt_hook.entries) {
        kvfree(decrypt_hook.entries);
        decrypt_hook.entries = NULL;
    }

    // Clean up any active uprobes
    for (i = 0; i < MAX_UPROBES; i++) {
        if (uprobes[i].active) {
            uprobe_unregister_nosync(uprobes[i].uprobe, &uprobes[i].consumer);
            if (uprobes[i].inode) {
                iput(uprobes[i].inode);
                uprobes[i].inode = NULL;
            }
            if (uprobes[i].hits) {
                kvfree(uprobes[i].hits);
                uprobes[i].hits = NULL;
            }
            uprobes[i].uprobe = NULL;
            uprobes[i].active = 0;
        }
    }
    uprobe_unregister_sync();  // Wait for all uprobe callbacks to complete

    // Stop syscall tracing if active
    if (syscall_state.active) {
        syscall_state.active = 0;
        if (tp_sys_enter) {
            tracepoint_probe_unregister(tp_sys_enter, syscall_trace_callback, NULL);
            tracepoint_synchronize_unregister();
        }
    }

    // Free syscall trace buffer
    if (syscall_state.buffer) {
        kvfree(syscall_state.buffer);
        syscall_state.buffer = NULL;
    }

    // Stop page monitor if running
    if (monitor_state.active && monitor_state.monitor_thread) {
        monitor_state.active = 0;
        kthread_stop(monitor_state.monitor_thread);
        monitor_state.monitor_thread = NULL;
    }

    // Free page monitor memory
    if (monitor_state.pages) {
        kvfree(monitor_state.pages);
        monitor_state.pages = NULL;
    }
    if (monitor_state.captures) {
        kvfree(monitor_state.captures);
        monitor_state.captures = NULL;
    }

    // Clean up any active breakpoints
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (breakpoints[i].active && breakpoints[i].bp_event) {
            unregister_hw_breakpoint(breakpoints[i].bp_event);
            breakpoints[i].active = 0;
            breakpoints[i].bp_event = NULL;
        }
    }

    device_destroy(memreader_class, MKDEV(major_number, 0));
    class_destroy(memreader_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "MemReader: Module unloaded\n");
}

module_init(memreader_init);
module_exit(memreader_exit);
