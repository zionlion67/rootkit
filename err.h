#ifndef _ERR_H
#define _ERR_H

#include <linux/printk.h>

#ifdef ZL_DEBUG
#define log_err(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#else
#define log_err(fmt, ...)
#endif

#endif
