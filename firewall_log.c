#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

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

static int get_l4_ports_ipv4(const struct sk_buff *skb,
                            const struct iphdr *iph,
                            __be16 *sport, __be16 *dport)
{
    unsigned int ip_hlen;
    void *th;
    struct tcphdr _tcph;
    struct udphdr _udph;

    if (!iph)
        return -1;

    ip_hlen = iph->ihl * 4;
    if (ip_hlen < sizeof(*iph))
        return -1;

    if (skb->len < ip_hlen)
        return -1;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        th = skb_header_pointer(skb, ip_hlen, sizeof(_tcph), &_tcph);
        if (!th)
            return -1;
        *sport = ((struct tcphdr *)th)->source;
        *dport = ((struct tcphdr *)th)->dest;
        return 0;

    case IPPROTO_UDP:
        th = skb_header_pointer(skb, ip_hlen, sizeof(_udph), &_udph);
        if (!th)
            return -1;
        *sport = ((struct udphdr *)th)->source;
        *dport = ((struct udphdr *)th)->dest;
        return 0;

    default:
        return -1;
    }
}

unsigned int hook_func(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){

const struct iphdr *iph;
const char *in = state->in ? state->in->name : "-";
const char *out = state->out ? state->out->name : "-";
__be16 sport = 0, dport = 0;
int have_ports = 0;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        if (get_l4_ports_ipv4(skb, iph, &sport, &dport) == 0)
            have_ports = 1;
    }

    if (have_ports) {
        printk(KERN_INFO "[fwlog] Hook:%s iif:%s oif:%s Proto:%s %pI4:%u -> %pI4:%u\n",
               hook_name(state->hook), in, out, proto_name(iph->protocol),
               &iph->saddr, ntohs(sport), &iph->daddr, ntohs(dport));
    } else {
        printk(KERN_INFO "[fwlog] Hook:%s iif:%s oif:%s Proto:%s Src:%pI4 Dst:%pI4\n",
               hook_name(state->hook), in, out, proto_name(iph->protocol),
               &iph->saddr, &iph->daddr);
    }

    return NF_ACCEPT;
}


static int __init logger_init(void){

    int i;
    int ret;

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
	
	 ret = nf_register_net_hook(&init_net, &nfho[i]);
        if (ret) {
            printk(KERN_ERR "[fwlog] Failed to register hook %s: %d\n",
                   hook_name(hooks[i]), ret);
        }
    }
    printk(KERN_INFO "[fwlog] Loaded. IPv4 hooks registered at all stages.\n");
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

