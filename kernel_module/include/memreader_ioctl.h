#ifndef MEMREADER_IOCTL_H
#define MEMREADER_IOCTL_H

#include <linux/ioctl.h>

#define MEMREADER_MAGIC 'M'

// ============================================================================
// Basic Memory Operations
// ============================================================================

// Structure for reading memory
struct memreader_read_request {
    int pid;                    // Target process ID
    unsigned long address;      // Memory address to read
    unsigned long size;         // Number of bytes to read
    void *buffer;              // User-space buffer to store data
};

// Structure for getting process base address
struct memreader_base_request {
    int pid;                    // Target process ID
    unsigned long base_address; // Output: base address of main executable
};

// ============================================================================
// Hardware Breakpoint Support
// ============================================================================

// Breakpoint types (matches x86 DR7 condition bits)
#define HWBP_TYPE_EXEC      0   // Break on execution
#define HWBP_TYPE_WRITE     1   // Break on write
#define HWBP_TYPE_READWRITE 3   // Break on read or write

// Breakpoint lengths (matches x86 DR7 length bits)
#define HWBP_LEN_1          0   // 1 byte
#define HWBP_LEN_2          1   // 2 bytes
#define HWBP_LEN_4          3   // 4 bytes
#define HWBP_LEN_8          2   // 8 bytes (x86_64 only)

// Structure for setting hardware breakpoint
struct memreader_hwbp_request {
    int pid;                    // Target process ID
    int bp_num;                 // Breakpoint number (0-3 for DR0-DR3)
    unsigned long address;      // Address to break on
    int type;                   // HWBP_TYPE_*
    int len;                    // HWBP_LEN_*
};

// Structure for breakpoint hit information
struct memreader_bp_hit_info {
    int pid;                    // Target process ID (input)
    int hit;                    // Output: 1 if breakpoint was hit, 0 otherwise
    int bp_num;                 // Output: which breakpoint (0-3) was hit
    unsigned long rip;          // Output: instruction pointer at hit
    unsigned long rsp;          // Output: stack pointer at hit
    unsigned long fault_addr;   // Output: faulting address (CR2)
    unsigned long dr6;          // Output: debug status register
    unsigned long timestamp;    // Output: jiffies when hit occurred
};

// ============================================================================
// Thread Register Reading
// ============================================================================

// Structure for reading thread registers
struct memreader_regs_request {
    int pid;                    // Target process ID
    int tid;                    // Thread ID (0 = main thread)
    // Output registers
    unsigned long rip;
    unsigned long rsp;
    unsigned long rbp;
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long rflags;
    unsigned long cs;
    unsigned long ss;
    unsigned long fs_base;      // FS segment base (TEB pointer on Wine/Windows)
    unsigned long gs_base;      // GS segment base
};

// Structure for enumerating threads
struct memreader_thread_list {
    int pid;                    // Target process ID
    int max_threads;            // Max entries in tids array
    int num_threads;            // Output: actual number of threads
    int *tids;                  // User buffer for thread IDs
};

// ============================================================================
// IOCTL Commands
// ============================================================================

// Basic operations
#define MEMREADER_READ_MEMORY   _IOWR(MEMREADER_MAGIC, 1, struct memreader_read_request)
#define MEMREADER_GET_BASE      _IOWR(MEMREADER_MAGIC, 2, struct memreader_base_request)

// Hardware breakpoint operations
#define MEMREADER_SET_HWBP      _IOW(MEMREADER_MAGIC, 10, struct memreader_hwbp_request)
#define MEMREADER_CLEAR_HWBP    _IOW(MEMREADER_MAGIC, 11, struct memreader_hwbp_request)
#define MEMREADER_GET_BP_HIT    _IOWR(MEMREADER_MAGIC, 12, struct memreader_bp_hit_info)
#define MEMREADER_CLEAR_BP_HIT  _IOW(MEMREADER_MAGIC, 13, struct memreader_bp_hit_info)

// Register operations
#define MEMREADER_READ_REGS     _IOWR(MEMREADER_MAGIC, 20, struct memreader_regs_request)
#define MEMREADER_LIST_THREADS  _IOWR(MEMREADER_MAGIC, 21, struct memreader_thread_list)

// ============================================================================
// Page Decryption Monitoring
// ============================================================================

#define MAX_WATCH_PAGES 2048
#define MAX_CAPTURE_THREADS 64
#define MAX_CAPTURES 32

// Configuration for page monitoring - uses pointer for page array
struct memreader_page_monitor_config {
    int pid;                            // Target process ID
    int num_pages;                      // Number of pages to watch (max MAX_WATCH_PAGES)
    int poll_interval_us;               // Polling interval in microseconds (min 100)
    unsigned long *pages;               // Pointer to userspace array of page addresses
};

// Captured thread state when decryption detected
struct memreader_thread_capture {
    int tid;                    // Thread ID
    unsigned long rip;          // Instruction pointer
    unsigned long rsp;          // Stack pointer
    unsigned long rbp;          // Base pointer
    unsigned long rax;          // Return/scratch register
    unsigned long stack[8];     // First 8 qwords from stack (return addresses)
};

// Single capture event (kept small for kernel storage)
struct memreader_capture_event {
    unsigned long page_addr;            // Which page was decrypted
    unsigned long timestamp;            // jiffies when detected
    int num_threads;                    // Number of threads captured
    struct memreader_thread_capture threads[MAX_CAPTURE_THREADS];
};

// Result of page monitor - uses pointer for captures array
struct memreader_decrypt_capture {
    int num_captures;                   // Number of captures available (output)
    int total_pages_decrypted;          // Total pages that decrypted (output)
    int still_monitoring;               // 1 if still running, 0 if stopped (output)
    int max_captures;                   // Size of captures array (input)
    struct memreader_capture_event *captures;  // Pointer to userspace array
};

// Monitor status
struct memreader_monitor_status {
    int active;                 // 1 if monitoring is active
    int pid;                    // Target PID
    int num_pages_watching;     // Number of pages being watched
    unsigned long polls;        // Number of poll cycles completed
    unsigned long pages_changed; // Number of pages that have changed
};

// Page monitor operations - use _IO for large struct commands
#define MEMREADER_START_PAGE_MONITOR _IOW(MEMREADER_MAGIC, 30, struct memreader_page_monitor_config)
#define MEMREADER_STOP_PAGE_MONITOR  _IO(MEMREADER_MAGIC, 31)
#define MEMREADER_GET_DECRYPT_CAPTURE _IOWR(MEMREADER_MAGIC, 32, struct memreader_decrypt_capture)
#define MEMREADER_GET_MONITOR_STATUS _IOR(MEMREADER_MAGIC, 33, struct memreader_monitor_status)

// ============================================================================
// Syscall Tracing
// ============================================================================

#define MAX_SYSCALL_TRACES 4096

// Single syscall trace entry
struct memreader_syscall_entry {
    unsigned long timestamp;        // jiffies when syscall occurred
    int pid;                        // Process ID
    int tid;                        // Thread ID
    unsigned long syscall_nr;       // Syscall number (after Wine translation = Linux syscall)
    unsigned long arg0;             // RDI
    unsigned long arg1;             // RSI
    unsigned long arg2;             // RDX
    unsigned long arg3;             // R10
    unsigned long arg4;             // R8
    unsigned long arg5;             // R9
    unsigned long ret;              // Return value (RAX after syscall)
    unsigned long rip;              // Instruction pointer (caller)
    int is_entry;                   // 1 = entry, 0 = exit
};

// Configuration for syscall tracing
struct memreader_syscall_config {
    int pid;                        // Target process ID (0 = all)
    int trace_entries;              // 1 = trace entries, 0 = skip
    int trace_exits;                // 1 = trace exits, 0 = skip
};

// Result buffer for retrieving traces
struct memreader_syscall_buffer {
    int max_entries;                // Size of entries array (input)
    int num_entries;                // Number of entries returned (output)
    int overflow;                   // 1 if ring buffer overflowed (output)
    struct memreader_syscall_entry *entries;  // Pointer to userspace array
};

// Syscall trace status
struct memreader_syscall_status {
    int active;                     // 1 if tracing is active
    int pid;                        // Target PID (0 = all)
    unsigned long total_syscalls;   // Total syscalls captured
    unsigned long dropped;          // Dropped due to buffer full
};

// Syscall tracing operations
#define MEMREADER_START_SYSCALL_TRACE _IOW(MEMREADER_MAGIC, 40, struct memreader_syscall_config)
#define MEMREADER_STOP_SYSCALL_TRACE  _IO(MEMREADER_MAGIC, 41)
#define MEMREADER_GET_SYSCALL_TRACES  _IOWR(MEMREADER_MAGIC, 42, struct memreader_syscall_buffer)
#define MEMREADER_GET_SYSCALL_STATUS  _IOR(MEMREADER_MAGIC, 43, struct memreader_syscall_status)
#define MEMREADER_CLEAR_SYSCALL_TRACES _IO(MEMREADER_MAGIC, 44)

// ============================================================================
// Uprobe Support (cross-thread instruction tracing)
// ============================================================================

#define MAX_UPROBE_HITS 256

// Structure for setting a uprobe
struct memreader_uprobe_request {
    int pid;                        // Target process ID
    unsigned long address;          // Virtual address to probe
    int probe_id;                   // Probe ID (0-7, for managing multiple probes)
};

// Captured register state when uprobe fires
struct memreader_uprobe_hit {
    unsigned long timestamp;        // jiffies when hit occurred
    int tid;                        // Thread ID that hit the probe
    unsigned long rip;              // Instruction pointer
    unsigned long rax;
    unsigned long rbx;              // <-- The key register we need!
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long rbp;
    unsigned long rsp;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
};

// Structure for retrieving uprobe hits
struct memreader_uprobe_hits {
    int probe_id;                   // Which probe to get hits for (input)
    int max_hits;                   // Max entries in hits array (input)
    int num_hits;                   // Number of hits returned (output)
    int total_hits;                 // Total hits since probe set (output)
    int overflow;                   // 1 if ring buffer overflowed (output)
    struct memreader_uprobe_hit *hits;  // Pointer to userspace array
};

// Uprobe status
struct memreader_uprobe_status {
    int probe_id;                   // Probe ID to query
    int active;                     // 1 if probe is active
    int pid;                        // Target PID
    unsigned long address;          // Probed address
    unsigned long total_hits;       // Total hits
    unsigned long file_offset;      // File offset used (for debugging)
};

// Uprobe operations
#define MEMREADER_SET_UPROBE        _IOW(MEMREADER_MAGIC, 50, struct memreader_uprobe_request)
#define MEMREADER_CLEAR_UPROBE      _IOW(MEMREADER_MAGIC, 51, struct memreader_uprobe_request)
#define MEMREADER_GET_UPROBE_HITS   _IOWR(MEMREADER_MAGIC, 52, struct memreader_uprobe_hits)
#define MEMREADER_GET_UPROBE_STATUS _IOWR(MEMREADER_MAGIC, 53, struct memreader_uprobe_status)
#define MEMREADER_CLEAR_UPROBE_HITS _IOW(MEMREADER_MAGIC, 54, struct memreader_uprobe_request)

// ============================================================================
// Decrypt Hook (Hardware Breakpoint with Full Register Capture for JIT code)
// ============================================================================

#define MAX_DECRYPT_CAPTURES 4096

// Captured decrypt operation - encrypted input and decrypted output
struct memreader_decrypt_entry {
    unsigned long timestamp;        // jiffies when captured
    int tid;                        // Thread ID that decrypted
    unsigned long rip;              // Instruction pointer at capture
    unsigned long encrypted;        // Input value (key/encrypted ptr)
    unsigned long decrypted;        // Output value (decrypted pointer in RAX)
    unsigned long rcx;              // RCX register (often used in decrypt)
    unsigned long rdx;              // RDX register (often used in decrypt)
    unsigned long r8;               // R8 register (XOR key in Theia)
    unsigned long r11;              // R11 register (decrypted target in Theia)
};

// Configuration for decrypt hook
struct memreader_decrypt_hook_config {
    int pid;                        // Target process ID
    unsigned long address;          // Address to hook (instruction AFTER decrypt completes)
    int tid;                        // Specific thread to capture (0 = all threads)
};

// Buffer for retrieving decrypt captures
struct memreader_decrypt_hook_buffer {
    int max_entries;                // Size of entries array (input)
    int num_entries;                // Number of entries returned (output)
    unsigned long total_captures;   // Total captures since hook set (output)
    int overflow;                   // 1 if ring buffer overflowed (output)
    int active;                     // 1 if hook is active (output)
    struct memreader_decrypt_entry *entries;  // Pointer to userspace array
};

// Decrypt hook status
struct memreader_decrypt_hook_status {
    int active;                     // 1 if hook is active
    int pid;                        // Target PID
    unsigned long address;          // Hooked address
    unsigned long total_captures;   // Total captures
    unsigned long unique_pointers;  // Unique decrypted values seen
};

// Decrypt hook operations
#define MEMREADER_SET_DECRYPT_HOOK    _IOW(MEMREADER_MAGIC, 60, struct memreader_decrypt_hook_config)
#define MEMREADER_CLEAR_DECRYPT_HOOK  _IO(MEMREADER_MAGIC, 61)
#define MEMREADER_GET_DECRYPT_ENTRIES _IOWR(MEMREADER_MAGIC, 62, struct memreader_decrypt_hook_buffer)
#define MEMREADER_CLEAR_DECRYPT_ENTRIES _IO(MEMREADER_MAGIC, 63)
#define MEMREADER_GET_DECRYPT_HOOK_STATUS _IOR(MEMREADER_MAGIC, 64, struct memreader_decrypt_hook_status)
#define MEMREADER_UPDATE_DECRYPT_HOOK _IO(MEMREADER_MAGIC, 65)  // Add breakpoints to new threads

#endif // MEMREADER_IOCTL_H
