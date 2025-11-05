#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho[5];

const char *hook_name(unsigned int hooknum) {
    switch (hooknum) {
        case NF_INET_PRE_ROUTING:  return "PRE_ROUTING";
        case NF_INET_LOCAL_IN:     return "LOCAL_IN";
        case NF_INET_FORWARD:      return "FORWARD";
        case NF_INET_LOCAL_OUT:    return "LOCAL_OUT";
        case NF_INET_POST_ROUTING: return "POST_ROUTING";
        default:                   return "UNKNOWN";
    }
}

const char *proto_name(unsigned int proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default:           return "OTHER";
    }
}


unsigned int hook_func(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){

	struct iphdr *iph = ip_hdr(skb);

	if(!iph) return NF_ACCEPT;

	printk(KERN_INFO "[fwlog] Hook: %s, Protocol: %s, Src: %pI4, Dst: %pI4\n",
		hook_name(state->hook), proto_name(iph->protocol), &iph->saddr, &iph->daddr);
	
	return NF_ACCEPT;
}


static int __init logger_init(void){

    int i;
    unsigned int hooks[] = {
        NF_INET_PRE_ROUTING,
        NF_INET_LOCAL_IN,
        NF_INET_FORWARD,
        NF_INET_LOCAL_OUT,
        NF_INET_POST_ROUTING
    };

    for (i = 0; i < 5; i++) {
        nfho[i].hook = hook_func;
        nfho[i].pf = PF_INET;
        nfho[i].hooknum = hooks[i];
        nfho[i].priority = NF_IP_PRI_FIRST;
        nf_register_net_hook(&init_net, &nfho[i]);
    }

    printk(KERN_INFO "Firewall logger loaded. Hooks registered for all IPv4 stages.\n");
    return 0;
}

static void __exit logger_exit(void)
{
    int i;
    for (i = 0; i < 5; i++)
        nf_unregister_net_hook(&init_net, &nfho[i]);

    printk(KERN_INFO "Firewall logger unloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");

