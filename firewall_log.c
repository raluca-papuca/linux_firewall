#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/timekeeping.h>
#include <net/ipv6.h>


static struct nf_hook_ops nfho4[5];
static struct nf_hook_ops nfho6[5];

static const char *hook_name(unsigned int hooknum) {
    switch (hooknum) {
        case NF_INET_PRE_ROUTING:  return "PRE_ROUTING";
        case NF_INET_LOCAL_IN:     return "LOCAL_IN";
        case NF_INET_FORWARD:      return "FORWARD";
        case NF_INET_LOCAL_OUT:    return "LOCAL_OUT";
        case NF_INET_POST_ROUTING: return "POST_ROUTING";
        default:                   return "UNKNOWN";
    }
}

static const char *l4_name(u8 proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
	case IPPROTO_ICMPV6: return "ICMPv6";       
	case IPPROTO_IGMP: return "IGMP";
        default:           return "OTHER";
    }
}

static void get_timestamps(char *buf, size_t buflen, u64 *mono_ms_out)
{
    struct timespec64 ts;
    struct tm tm;
    u64 mono_ns;

    mono_ns = ktime_get_ns();
    if (mono_ms_out)
        *mono_ms_out = mono_ns / 1000000ULL;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm); 

    snprintf(buf, buflen,
             "%04ld-%02d-%02dT%02d:%02d:%02dZ.%09ld",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
}


static int get_l4_ports_ipv4(const struct sk_buff *skb,
                            const struct iphdr *iph,
                            __be16 *sport, __be16 *dport)
{
    unsigned int ip_hlen;
    void *th;
    struct tcphdr _tcph;
    struct udphdr _udph;

    if (!iph || !skb)
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

static int get_l4_ports_ipv6(const struct sk_buff *skb,
                             const struct ipv6hdr *ip6h,
                             u8 *l4proto,
                             __be16 *sport, __be16 *dport)
{
    int offset;
    u8 nexthdr;
    __be16 frag_off = 0;
    void *th;
    struct tcphdr _tcph;
    struct udphdr _udph;

    if (!skb || !ip6h || !l4proto)
        return -1;

    offset = sizeof(struct ipv6hdr);
    nexthdr = ip6h->nexthdr;

    offset = ipv6_skip_exthdr(skb, offset, &nexthdr, &frag_off);
    if (offset < 0)
        return -1;

    *l4proto = nexthdr;

    switch (nexthdr) {
    case IPPROTO_TCP:
        th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
        if (!th)
            return -1;
        *sport = ((struct tcphdr *)th)->source;
        *dport = ((struct tcphdr *)th)->dest;
        return 0;

    case IPPROTO_UDP:
        th = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
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


const char *in = state->in ? state->in->name : "-";
const char *out = state->out ? state->out->name : "-";
char utc[64];
u64 mono_ms = 0;

get_timestamps(utc, sizeof(utc), &mono_ms);

    if (!skb)
        return NF_ACCEPT;

    if(state->pf == NFPROTO_IPV4){
	const struct iphdr *iph = ip_hdr(skb);
	__be16 sport = 0, dport = 0;
	int have_ports = 0;

	if (!iph)
	  return NF_ACCEPT;

	if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) &&
            get_l4_ports_ipv4(skb, iph, &sport, &dport) == 0) {
            have_ports = 1;
	}

	if (have_ports) {
            printk(KERN_INFO
                   "[fwlog][utc=%s mono=%llums] Hook:%s iif:%s oif:%s "
                   "IPv4 %s %pI4:%u -> %pI4:%u len:%u\n",
                   utc, (unsigned long long)mono_ms,
                   hook_name(state->hook), in, out,
                   l4_name(iph->protocol),
                   &iph->saddr, ntohs(sport),
                   &iph->daddr, ntohs(dport),
                   skb->len);
        } else {
            printk(KERN_INFO
                   "[fwlog][utc=%s mono=%llums] Hook:%s iif:%s oif:%s "
                   "IPv4 %s Src:%pI4 Dst:%pI4 len:%u\n",
                   utc, (unsigned long long)mono_ms,
                   hook_name(state->hook), in, out,
                   l4_name(iph->protocol),
                   &iph->saddr, &iph->daddr,
                   skb->len);
        }

        return NF_ACCEPT;
    }

    if (state->pf == NFPROTO_IPV6) {
        const struct ipv6hdr *ip6h = ipv6_hdr(skb);
        __be16 sport = 0, dport = 0;
        u8 l4proto = 0;
        int have_ports = 0;

        if (!ip6h)
            return NF_ACCEPT;

        if (get_l4_ports_ipv6(skb, ip6h, &l4proto, &sport, &dport) == 0)
            have_ports = 1;
        else
            l4proto = ip6h->nexthdr;

        if (have_ports) {
            printk(KERN_INFO
                   "[fwlog][utc=%s mono=%llums] Hook:%s iif:%s oif:%s "
                   "IPv6 %s %pI6c:%u -> %pI6c:%u len:%u\n",
                   utc, (unsigned long long)mono_ms,
                   hook_name(state->hook), in, out,
                   l4_name(l4proto),
                   &ip6h->saddr, ntohs(sport),
                   &ip6h->daddr, ntohs(dport),
                   skb->len);
        } else {
            printk(KERN_INFO
                   "[fwlog][utc=%s mono=%llums] Hook:%s iif:%s oif:%s "
                   "IPv6 %s Src:%pI6c Dst:%pI6c len:%u\n",
                   utc, (unsigned long long)mono_ms,
                   hook_name(state->hook), in, out,
                   l4_name(l4proto),
                   &ip6h->saddr, &ip6h->daddr,
                   skb->len);
        }

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

static int register_hooks(struct nf_hook_ops *ops, u8 pf)
{
    int i, ret;
    unsigned int hooks[] = {
        NF_INET_PRE_ROUTING,
        NF_INET_LOCAL_IN,
        NF_INET_FORWARD,
        NF_INET_LOCAL_OUT,
        NF_INET_POST_ROUTING
    };

    for (i = 0; i < 5; i++) {
        ops[i].hook = hook_func;
        ops[i].pf = pf;
        ops[i].hooknum = hooks[i];
        ops[i].priority = NF_IP_PRI_FIRST;

        ret = nf_register_net_hook(&init_net, &ops[i]);
        if (ret) {
            printk(KERN_ERR "[fwlog] Failed to register %s for pf=%u: %d\n",
                   hook_name(hooks[i]), pf, ret);
        }
    }
    return 0;
}

static void unregister_hooks(struct nf_hook_ops *ops)
{
    int i;
    for (i = 0; i < 5; i++)
        nf_unregister_net_hook(&init_net, &ops[i]);
}


static int __init logger_init(void)
{
    register_hooks(nfho4, PF_INET);
    register_hooks(nfho6, PF_INET6);

    printk(KERN_INFO "[fwlog] Loaded. Hooks registered for IPv4 and IPv6.\n");
    return 0;
}

static void __exit logger_exit(void)
{
    unregister_hooks(nfho4);
    unregister_hooks(nfho6);

    printk(KERN_INFO "[fwlog] Unloaded.\n");
}

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");

