#ifndef _PAGE_PROT_H
#define _PAGE_PROT_H

#include <asm/special_insns.h>
#include <asm/processor-flags.h>
#include <linux/preempt.h>

void set_page_ro(void *addr);
void set_page_rw(void *addr);

static inline void disable_wp(void)
{
	unsigned long cr0;
	preempt_disable();
	cr0 = read_cr0();
	cr0 ^= X86_CR0_WP;
	write_cr0(cr0);
}

static inline void enable_wp(void)
{
	unsigned long cr0;
	cr0 = read_cr0();
	cr0 ^= X86_CR0_WP;
	write_cr0(cr0);
	barrier();
	preempt_enable();
}
#endif
