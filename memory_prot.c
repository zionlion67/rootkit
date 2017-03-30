#include <linux/mm.h>
#include "memory_prot.h"
#include "err.h"

void set_page_ro(void *addr)
{
	unsigned int l;
	/* lookup page table entry for a given virtual address */
	pte_t *pte = lookup_address((unsigned long)addr, &l);
	if (pte_write(*pte))
		pte_wrprotect(*pte);
	else
		log_err("pte is already read-only\n");
}

void set_page_wr(void *addr)
{
	unsigned int l;
	pte_t *pte = lookup_address((unsigned long)addr, &l);
	if (!pte_write(*pte))
		pte_mkwrite(*pte);
	else
		log_err("pte is already writable\n");
}
