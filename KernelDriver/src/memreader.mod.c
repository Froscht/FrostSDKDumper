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
	{ 0xd272d446, "synchronize_rcu_tasks_trace" },
	{ 0xd272d446, "synchronize_rcu" },
	{ 0x0571dc46, "kthread_stop" },
	{ 0x1595e410, "device_destroy" },
	{ 0xa1dacb42, "class_destroy" },
	{ 0x52b15b3b, "__unregister_chrdev" },
	{ 0xb1ad3f2f, "boot_cpu_data" },
	{ 0x211f9d4e, "mem_section" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0xa53f4e29, "memcpy" },
	{ 0xd272d446, "__SCT__preempt_schedule" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0x1c489eb6, "register_kprobe" },
	{ 0x7a8e92c6, "unregister_kprobe" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x1cf09ab5, "__put_task_struct_rcu_cb" },
	{ 0xb9fcd065, "call_rcu" },
	{ 0x2520ea93, "refcount_warn_saturate" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0x37031a65, "__register_chrdev" },
	{ 0x653aa194, "class_create" },
	{ 0xe486c4b7, "device_create" },
	{ 0xf296206e, "pgdir_shift" },
	{ 0x095159b2, "physical_mask" },
	{ 0x1bdf2bc8, "sme_me_mask" },
	{ 0xf296206e, "ptrs_per_p4d" },
	{ 0x6f8082dd, "pv_ops" },
	{ 0xd272d446, "BUG_func" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x5e505530, "kthread_should_stop" },
	{ 0xb0e4fe1f, "find_get_pid" },
	{ 0x848a0d8d, "get_pid_task" },
	{ 0x920e864e, "put_pid" },
	{ 0xbf2c538b, "get_task_mm" },
	{ 0x73c05ac1, "__tracepoint_mmap_lock_start_locking" },
	{ 0xa59da3c0, "down_read" },
	{ 0x73c05ac1, "__tracepoint_mmap_lock_acquire_returned" },
	{ 0x73c05ac1, "__tracepoint_mmap_lock_released" },
	{ 0xa59da3c0, "up_read" },
	{ 0xcf46e6bd, "mmput" },
	{ 0x0feb1e94, "usleep_range_state" },
	{ 0xaedbc175, "__mmap_lock_do_trace_acquire_returned" },
	{ 0x2287b539, "__mmap_lock_do_trace_start_locking" },
	{ 0x2287b539, "__mmap_lock_do_trace_released" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0xbc222a7b, "register_user_hw_breakpoint" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x27683a56, "memset" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0xf52f8b44, "__kvmalloc_node_noprof" },
	{ 0x9667e18b, "tracepoint_probe_register" },
	{ 0x0ca0353a, "mas_find" },
	{ 0xa285c273, "mtree_load" },
	{ 0xfd64218d, "ihold" },
	{ 0xca4aed6f, "uprobe_register" },
	{ 0x7f79e79a, "kthread_create_on_node" },
	{ 0x630dad60, "wake_up_process" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x2719b9fa, "const_current_task" },
	{ 0x058c185a, "jiffies" },
	{ 0xe1e1f979, "_raw_spin_lock_irqsave" },
	{ 0x81a1a811, "_raw_spin_unlock_irqrestore" },
	{ 0xff7fbdd1, "___ratelimit" },
	{ 0xe8213e80, "_printk" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0x51215b83, "unregister_hw_breakpoint" },
	{ 0xf1de9e85, "kvfree" },
	{ 0xa628c5cc, "uprobe_unregister_nosync" },
	{ 0xfd64218d, "iput" },
	{ 0xd272d446, "uprobe_unregister_sync" },
	{ 0x9667e18b, "tracepoint_probe_unregister" },
	{ 0xbebe66ff, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0xd272d446,
	0x0571dc46,
	0x1595e410,
	0xa1dacb42,
	0x52b15b3b,
	0xb1ad3f2f,
	0x211f9d4e,
	0x7ec472ba,
	0xbd03ed67,
	0xbd03ed67,
	0xa53f4e29,
	0xd272d446,
	0xbd03ed67,
	0xf46d5bf3,
	0x1c489eb6,
	0x7a8e92c6,
	0xf46d5bf3,
	0xd272d446,
	0xe4de56b4,
	0x1cf09ab5,
	0xb9fcd065,
	0x2520ea93,
	0x5a844b26,
	0x37031a65,
	0x653aa194,
	0xe486c4b7,
	0xf296206e,
	0x095159b2,
	0x1bdf2bc8,
	0xf296206e,
	0x6f8082dd,
	0xd272d446,
	0x82fd7238,
	0x5e505530,
	0xb0e4fe1f,
	0x848a0d8d,
	0x920e864e,
	0xbf2c538b,
	0x73c05ac1,
	0xa59da3c0,
	0x73c05ac1,
	0x73c05ac1,
	0xa59da3c0,
	0xcf46e6bd,
	0x0feb1e94,
	0xaedbc175,
	0x2287b539,
	0x2287b539,
	0xd272d446,
	0xd272d446,
	0xbc222a7b,
	0xd710adbf,
	0x546c19d9,
	0xa61fd7aa,
	0x092a35a2,
	0xcb8b6ec6,
	0x27683a56,
	0xe54e0a6b,
	0x092a35a2,
	0xf52f8b44,
	0x9667e18b,
	0x0ca0353a,
	0xa285c273,
	0xfd64218d,
	0xca4aed6f,
	0x7f79e79a,
	0x630dad60,
	0xd272d446,
	0xd272d446,
	0x2719b9fa,
	0x058c185a,
	0xe1e1f979,
	0x81a1a811,
	0xff7fbdd1,
	0xe8213e80,
	0x90a48d82,
	0x51215b83,
	0xf1de9e85,
	0xa628c5cc,
	0xfd64218d,
	0xd272d446,
	0x9667e18b,
	0xbebe66ff,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"synchronize_rcu_tasks_trace\0"
	"synchronize_rcu\0"
	"kthread_stop\0"
	"device_destroy\0"
	"class_destroy\0"
	"__unregister_chrdev\0"
	"boot_cpu_data\0"
	"mem_section\0"
	"__preempt_count\0"
	"vmemmap_base\0"
	"page_offset_base\0"
	"memcpy\0"
	"__SCT__preempt_schedule\0"
	"__ref_stack_chk_guard\0"
	"mutex_lock\0"
	"register_kprobe\0"
	"unregister_kprobe\0"
	"mutex_unlock\0"
	"__stack_chk_fail\0"
	"__ubsan_handle_load_invalid_value\0"
	"__put_task_struct_rcu_cb\0"
	"call_rcu\0"
	"refcount_warn_saturate\0"
	"__x86_indirect_thunk_rax\0"
	"__register_chrdev\0"
	"class_create\0"
	"device_create\0"
	"pgdir_shift\0"
	"physical_mask\0"
	"sme_me_mask\0"
	"ptrs_per_p4d\0"
	"pv_ops\0"
	"BUG_func\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"kthread_should_stop\0"
	"find_get_pid\0"
	"get_pid_task\0"
	"put_pid\0"
	"get_task_mm\0"
	"__tracepoint_mmap_lock_start_locking\0"
	"down_read\0"
	"__tracepoint_mmap_lock_acquire_returned\0"
	"__tracepoint_mmap_lock_released\0"
	"up_read\0"
	"mmput\0"
	"usleep_range_state\0"
	"__mmap_lock_do_trace_acquire_returned\0"
	"__mmap_lock_do_trace_start_locking\0"
	"__mmap_lock_do_trace_released\0"
	"__rcu_read_lock\0"
	"__rcu_read_unlock\0"
	"register_user_hw_breakpoint\0"
	"__kmalloc_noprof\0"
	"validate_usercopy_range\0"
	"__check_object_size\0"
	"_copy_to_user\0"
	"kfree\0"
	"memset\0"
	"__fortify_panic\0"
	"_copy_from_user\0"
	"__kvmalloc_node_noprof\0"
	"tracepoint_probe_register\0"
	"mas_find\0"
	"mtree_load\0"
	"ihold\0"
	"uprobe_register\0"
	"kthread_create_on_node\0"
	"wake_up_process\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"const_current_task\0"
	"jiffies\0"
	"_raw_spin_lock_irqsave\0"
	"_raw_spin_unlock_irqrestore\0"
	"___ratelimit\0"
	"_printk\0"
	"__ubsan_handle_out_of_bounds\0"
	"unregister_hw_breakpoint\0"
	"kvfree\0"
	"uprobe_unregister_nosync\0"
	"iput\0"
	"uprobe_unregister_sync\0"
	"tracepoint_probe_unregister\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "CFE9A610A1D42642CB2848A");
