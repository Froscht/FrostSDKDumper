#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xb6377019, "register_kprobe" },
	{ 0x2de0a194, "unregister_kprobe" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x5662e8b0, "uprobe_unregister_nosync" },
	{ 0xf792861b, "iput" },
	{ 0xd272d446, "uprobe_unregister_sync" },
	{ 0x3f5d9e57, "tracepoint_probe_unregister" },
	{ 0xd272d446, "synchronize_rcu" },
	{ 0x2794f3c0, "kthread_stop" },
	{ 0xbeb1d261, "__flush_workqueue" },
	{ 0xbeb1d261, "destroy_workqueue" },
	{ 0x408a0738, "device_destroy" },
	{ 0xd7442be0, "class_destroy" },
	{ 0x52b15b3b, "__unregister_chrdev" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xc4fee520, "kmalloc_caches" },
	{ 0x4574d0c7, "__kmalloc_cache_noprof" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xb5214c4c, "__register_chrdev" },
	{ 0xfad798b2, "class_create" },
	{ 0x02106a3d, "device_create" },
	{ 0xdf4bee3d, "alloc_workqueue_noprof" },
	{ 0x3f5d9e57, "tracepoint_probe_register" },
	{ 0xf312e20b, "__tracepoint_mmap_lock_released" },
	{ 0x8efcc8cd, "up_read" },
	{ 0x95896bdf, "__mmap_lock_do_trace_released" },
	{ 0xf312e20b, "__tracepoint_mmap_lock_start_locking" },
	{ 0x8efcc8cd, "down_read" },
	{ 0xf312e20b, "__tracepoint_mmap_lock_acquire_returned" },
	{ 0x95896bdf, "__mmap_lock_do_trace_start_locking" },
	{ 0x81af0025, "__mmap_lock_do_trace_acquire_returned" },
	{ 0x1cf09ab5, "__put_task_struct_rcu_cb" },
	{ 0xb9fcd065, "call_rcu" },
	{ 0xff0106da, "refcount_warn_saturate" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0xf296206e, "pgdir_shift" },
	{ 0x095159b2, "physical_mask" },
	{ 0x1bdf2bc8, "sme_me_mask" },
	{ 0xf296206e, "ptrs_per_p4d" },
	{ 0x024101ca, "pv_ops" },
	{ 0xd272d446, "BUG_func" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x5e505530, "kthread_should_stop" },
	{ 0x919f8814, "get_task_mm" },
	{ 0x402db74e, "memcmp" },
	{ 0x6358dda3, "mmput" },
	{ 0x0feb1e94, "usleep_range_state" },
	{ 0xca31368d, "kthread_create_on_node" },
	{ 0x42baf079, "wake_up_process" },
	{ 0x0e9cab28, "memset" },
	{ 0x8e650c77, "register_user_hw_breakpoint" },
	{ 0x29311525, "mas_find" },
	{ 0x88ee2324, "d_path" },
	{ 0x296b9459, "strrchr" },
	{ 0x2435d559, "strncmp" },
	{ 0x82dca728, "access_process_vm" },
	{ 0x7851be11, "__SCT__cond_resched" },
	{ 0x9479a1e8, "strnlen" },
	{ 0xd70733be, "sized_strscpy" },
	{ 0xc36fcc0c, "mtree_load" },
	{ 0xf792861b, "ihold" },
	{ 0x16d779e5, "uprobe_register" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x5649a64f, "unregister_hw_breakpoint" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x8b881dc5, "const_current_task" },
	{ 0x058c185a, "jiffies" },
	{ 0x11f4259a, "_raw_spin_lock_irqsave" },
	{ 0x444885a7, "_raw_spin_unlock_irqrestore" },
	{ 0x68a1b6c6, "__wake_up" },
	{ 0xf1e27da8, "rcu_tasks_trace_srcu_struct" },
	{ 0x311795f9, "synchronize_srcu" },
	{ 0x12400a07, "tracepoint_srcu" },
	{ 0xd32f43c7, "find_get_pid" },
	{ 0xa395d6d6, "get_pid_task" },
	{ 0xe6f5692d, "put_pid" },
	{ 0xb1ad3f2f, "boot_cpu_data" },
	{ 0x211f9d4e, "mem_section" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0xfbe7861b, "memcpy" },
	{ 0xd272d446, "__SCT__preempt_schedule" },
	{ 0x0e675b65, "___ratelimit" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xe8213e80, "_printk" },
	{ 0x7057d579, "mutex_trylock" },
	{ 0x9aa6980d, "mutex_unlock" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0x9aa6980d, "mutex_lock" },
	{ 0xc5eb118c, "__kvmalloc_node_noprof" },
	{ 0x5cb46e6d, "validate_usercopy_range" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xf1de9e85, "kvfree" },
	{ 0xe9196a28, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0xe54e0a6b,
	0xb6377019,
	0x2de0a194,
	0xe4de56b4,
	0x5662e8b0,
	0xf792861b,
	0xd272d446,
	0x3f5d9e57,
	0xd272d446,
	0x2794f3c0,
	0xbeb1d261,
	0xbeb1d261,
	0x408a0738,
	0xd7442be0,
	0x52b15b3b,
	0xbd03ed67,
	0xc4fee520,
	0x4574d0c7,
	0x49733ad6,
	0x5a844b26,
	0xb5214c4c,
	0xfad798b2,
	0x02106a3d,
	0xdf4bee3d,
	0x3f5d9e57,
	0xf312e20b,
	0x8efcc8cd,
	0x95896bdf,
	0xf312e20b,
	0x8efcc8cd,
	0xf312e20b,
	0x95896bdf,
	0x81af0025,
	0x1cf09ab5,
	0xb9fcd065,
	0xff0106da,
	0xd710adbf,
	0xd272d446,
	0xd272d446,
	0xf296206e,
	0x095159b2,
	0x1bdf2bc8,
	0xf296206e,
	0x024101ca,
	0xd272d446,
	0x82fd7238,
	0x5e505530,
	0x919f8814,
	0x402db74e,
	0x6358dda3,
	0x0feb1e94,
	0xca31368d,
	0x42baf079,
	0x0e9cab28,
	0x8e650c77,
	0x29311525,
	0x88ee2324,
	0x296b9459,
	0x2435d559,
	0x82dca728,
	0x7851be11,
	0x9479a1e8,
	0xd70733be,
	0xc36fcc0c,
	0xf792861b,
	0x16d779e5,
	0xd272d446,
	0xd272d446,
	0x5649a64f,
	0xcb8b6ec6,
	0x8b881dc5,
	0x058c185a,
	0x11f4259a,
	0x444885a7,
	0x68a1b6c6,
	0xf1e27da8,
	0x311795f9,
	0x12400a07,
	0xd32f43c7,
	0xa395d6d6,
	0xe6f5692d,
	0xb1ad3f2f,
	0x211f9d4e,
	0x7ec472ba,
	0xbd03ed67,
	0xbd03ed67,
	0xfbe7861b,
	0xd272d446,
	0x0e675b65,
	0x90a48d82,
	0xe8213e80,
	0x7057d579,
	0x9aa6980d,
	0xbd03ed67,
	0x092a35a2,
	0x9aa6980d,
	0xc5eb118c,
	0x5cb46e6d,
	0xa61fd7aa,
	0x092a35a2,
	0xf1de9e85,
	0xe9196a28,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__stack_chk_fail\0"
	"__fortify_panic\0"
	"register_kprobe\0"
	"unregister_kprobe\0"
	"__ubsan_handle_load_invalid_value\0"
	"uprobe_unregister_nosync\0"
	"iput\0"
	"uprobe_unregister_sync\0"
	"tracepoint_probe_unregister\0"
	"synchronize_rcu\0"
	"kthread_stop\0"
	"__flush_workqueue\0"
	"destroy_workqueue\0"
	"device_destroy\0"
	"class_destroy\0"
	"__unregister_chrdev\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"queue_work_on\0"
	"__x86_indirect_thunk_rax\0"
	"__register_chrdev\0"
	"class_create\0"
	"device_create\0"
	"alloc_workqueue_noprof\0"
	"tracepoint_probe_register\0"
	"__tracepoint_mmap_lock_released\0"
	"up_read\0"
	"__mmap_lock_do_trace_released\0"
	"__tracepoint_mmap_lock_start_locking\0"
	"down_read\0"
	"__tracepoint_mmap_lock_acquire_returned\0"
	"__mmap_lock_do_trace_start_locking\0"
	"__mmap_lock_do_trace_acquire_returned\0"
	"__put_task_struct_rcu_cb\0"
	"call_rcu\0"
	"refcount_warn_saturate\0"
	"__kmalloc_noprof\0"
	"__rcu_read_lock\0"
	"__rcu_read_unlock\0"
	"pgdir_shift\0"
	"physical_mask\0"
	"sme_me_mask\0"
	"ptrs_per_p4d\0"
	"pv_ops\0"
	"BUG_func\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"kthread_should_stop\0"
	"get_task_mm\0"
	"memcmp\0"
	"mmput\0"
	"usleep_range_state\0"
	"kthread_create_on_node\0"
	"wake_up_process\0"
	"memset\0"
	"register_user_hw_breakpoint\0"
	"mas_find\0"
	"d_path\0"
	"strrchr\0"
	"strncmp\0"
	"access_process_vm\0"
	"__SCT__cond_resched\0"
	"strnlen\0"
	"sized_strscpy\0"
	"mtree_load\0"
	"ihold\0"
	"uprobe_register\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"unregister_hw_breakpoint\0"
	"kfree\0"
	"const_current_task\0"
	"jiffies\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_unlock_irqrestore\0"
	"__wake_up\0"
	"rcu_tasks_trace_srcu_struct\0"
	"synchronize_srcu\0"
	"tracepoint_srcu\0"
	"find_get_pid\0"
	"get_pid_task\0"
	"put_pid\0"
	"boot_cpu_data\0"
	"mem_section\0"
	"__preempt_count\0"
	"vmemmap_base\0"
	"page_offset_base\0"
	"memcpy\0"
	"__SCT__preempt_schedule\0"
	"___ratelimit\0"
	"__ubsan_handle_out_of_bounds\0"
	"_printk\0"
	"mutex_trylock\0"
	"mutex_unlock\0"
	"__ref_stack_chk_guard\0"
	"_copy_from_user\0"
	"mutex_lock\0"
	"__kvmalloc_node_noprof\0"
	"validate_usercopy_range\0"
	"__check_object_size\0"
	"_copy_to_user\0"
	"kvfree\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "B0DD0A671A0999E349EFCD2");
