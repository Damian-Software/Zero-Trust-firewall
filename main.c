#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damian Zeleny");
MODULE_DESCRIPTION("Zero-Trust Firewall (Kernel)");
MODULE_VERSION("1.0");

// ---------------- Configuration ----------------
static ushort AUTH_PORT = 40000;
static ushort PROTECTED_PORT = 9000;
static uint   ALLOW_TTL_SEC = 30;

module_param(AUTH_PORT, ushort, 0644);
module_param(PROTECTED_PORT, ushort, 0644);
module_param(ALLOW_TTL_SEC, uint, 0644);

// ---------------- Flow table ----------------
#define FLOW_BITS 10

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 dst_port;
    u8 proto;
};

struct flow_entry {
    struct flow_key key;
    unsigned long expires;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(flow_table, FLOW_BITS);
static DEFINE_SPINLOCK(flow_lock);
static struct timer_list gc_timer;

// ---------------- Helpers ----------------
static bool flow_match(struct flow_key *a, struct flow_key *b)
{
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static bool flow_allowed(struct flow_key *key)
{
    struct flow_entry *e;
    bool ok = false;

    spin_lock_bh(&flow_lock);
    hash_for_each_possible(flow_table, e, node, (u32)key->src_ip) {
        if (flow_match(&e->key, key) &&
            time_before(jiffies, e->expires)) {
            ok = true;
            break;
        }
    }
    spin_unlock_bh(&flow_lock);

    return ok;
}

static void flow_add(struct flow_key *key)
{
    struct flow_entry *e;

    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (!e)
        return;

    e->key = *key;
    e->expires = jiffies + ALLOW_TTL_SEC * HZ;

    spin_lock_bh(&flow_lock);
    hash_add(flow_table, &e->node, (u32)key->src_ip);
    spin_unlock_bh(&flow_lock);
}

// ---------------- Garbage Collection ----------------
static void flow_gc(struct timer_list *t)
{
    struct flow_entry *e;
    struct hlist_node *tmp;
    int bkt;

    spin_lock_bh(&flow_lock);
    hash_for_each_safe(flow_table, bkt, tmp, e, node) {
        if (time_after(jiffies, e->expires)) {
            hash_del(&e->node);
            kfree(e);
        }
    }
    spin_unlock_bh(&flow_lock);

    mod_timer(&gc_timer, jiffies + 5 * HZ);
}

// ---------------- Netfilter Hook ----------------
static unsigned int fw_hook(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct flow_key key;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto  = iph->protocol;

    // ---------- UDP ----------
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph;

        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*udph)))
            return NF_ACCEPT;

        udph = udp_hdr(skb);
        key.dst_port = udph->dest;

        // AUTH packet
        if (ntohs(udph->dest) == AUTH_PORT) {
            flow_add(&key);
            printk(KERN_INFO "ztfw: AUTH OK from %pI4\n", &iph->saddr);
            return NF_ACCEPT;
        }

        // Protected port
        if (ntohs(udph->dest) == PROTECTED_PORT) {
            if (flow_allowed(&key))
                return NF_ACCEPT;

            printk(KERN_INFO "ztfw: DROP UDP %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

    // ---------- TCP ----------
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;

        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*tcph)))
            return NF_ACCEPT;

        tcph = tcp_hdr(skb);
        key.dst_port = tcph->dest;

        if (ntohs(tcph->dest) == PROTECTED_PORT) {
            if (flow_allowed(&key))
                return NF_ACCEPT;

            printk(KERN_INFO "ztfw: DROP TCP %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// ---------------- Init / Exit ----------------
static struct nf_hook_ops nfho;

static int __init fw_init(void)
{
    hash_init(flow_table);

    nfho.hook = fw_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    timer_setup(&gc_timer, flow_gc, 0);
    mod_timer(&gc_timer, jiffies + 5 * HZ);

    printk(KERN_INFO "ztfw: loaded (AUTH_PORT=%u PROTECTED_PORT=%u TTL=%u)\n",
           AUTH_PORT, PROTECTED_PORT, ALLOW_TTL_SEC);

    return 0;
}

static void __exit fw_exit(void)
{
    del_timer_sync(&gc_timer);
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "ztfw: unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
