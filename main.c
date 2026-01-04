// fwk.c - Linux kernel firewall template (Netfilter hook)
// Build: make (see Makefile below)
// Load:  sudo insmod fwk.ko
// Unload:sudo rmmod fwk
//
// Design:
// - Stateless: drop everything to PROTECTED_PORT unless allowed
// - SPA AUTH packet: UDP to AUTH_PORT with a small header + tag
// - On valid AUTH: allow src_ip -> dst_port for a short time (flow table)
// - Data packets to PROTECTED_PORT: allowed only if flow exists
//
// NOTE: The "auth tag" here is NOT real crypto. Replace verify_auth() with HMAC/Ed25519.
// Kernel crypto API exists, but keep this template minimal.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Template");
MODULE_DESCRIPTION("Kernel firewall template with SPA-like authorization");
MODULE_VERSION("0.1");

// -------------------- Config --------------------
static ushort AUTH_PORT = 40000;       // SPA/auth packets come here (UDP)
module_param(AUTH_PORT, ushort, 0644);
MODULE_PARM_DESC(AUTH_PORT, "UDP port for auth packets");

static ushort PROTECTED_PORT = 9000;   // protect this destination port (UDP+TCP)
module_param(PROTECTED_PORT, ushort, 0644);
MODULE_PARM_DESC(PROTECTED_PORT, "Protected destination port");

// allow duration (seconds) after successful auth
static uint ALLOW_TTL_SEC = 30;
module_param(ALLOW_TTL_SEC, uint, 0644);
MODULE_PARM_DESC(ALLOW_TTL_SEC, "How long to allow a flow after auth (seconds)");

// flow table size: 2^N buckets
#define FLOW_BITS 10  // 1024 buckets
#define FLOW_GC_INTERVAL_SEC 5

// -------------------- SPA wire (demo) --------------------
// Minimal header inside UDP payload for AUTH packets.
#define SPA_MAGIC 0x53504131u /* 'SPA1' */

struct spa_msg {
    __be32 magic;      // SPA_MAGIC
    __be16 version;    // 1
    __be16 dst_port;   // port to allow (usually PROTECTED_PORT)
    __be64 ts_sec;     // unix-like seconds (demo)
    __be64 tag;        // demo "signature"
} __attribute__((packed));

// Demo secret for tag (replace!)
static const u64 DEMO_SECRET = 0xC0FFEE1234ABCDEFULL;

// -------------------- Flow table --------------------
struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 dst_port;
    u8     proto; // IPPROTO_TCP/IPPROTO_UDP
};

struct flow_entry {
    struct flow_key key;
    unsigned long expires_jiffies;
    struct hlist_node hnode;
};

static DEFINE_HASHTABLE(flow_ht, FLOW_BITS);
static DEFINE_SPINLOCK(flow_lock);

static struct nf_hook_ops nfho;
static struct timer_list gc_timer;

// -------------------- Utils --------------------
static inline u32 flow_hash_key(const struct flow_key *k)
{
    // simple hash; kernel has jhash but keep minimal
    u32 h = (u32)k->src_ip ^ (u32)k->dst_ip;
    h ^= ((u32)k->dst_port << 16) | (u32)k->proto;
    // fold a bit
    h ^= (h >> 16);
    return h;
}

static bool flow_key_eq(const struct flow_key *a, const struct flow_key *b)
{
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

static bool flow_is_allowed(const struct flow_key *k)
{
    struct flow_entry *e;
    bool ok = false;
    u32 h = flow_hash_key(k);

    spin_lock_bh(&flow_lock);
    hash_for_each_possible(flow_ht, e, hnode, h) {
        if (flow_key_eq(&e->key, k)) {
            if (time_before(jiffies, e->expires_jiffies)) {
                ok = true;
            }
            break;
        }
    }
    spin_unlock_bh(&flow_lock);
    return ok;
}

static void flow_allow(const struct flow_key *k)
{
    struct flow_entry *e;
    u32 h = flow_hash_key(k);

    spin_lock_bh(&flow_lock);

    // update if exists
    hash_for_each_possible(flow_ht, e, hnode, h) {
        if (flow_key_eq(&e->key, k)) {
            e->expires_jiffies = jiffies + (ALLOW_TTL_SEC * HZ);
            spin_unlock_bh(&flow_lock);
            return;
        }
    }

    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (!e) {
        spin_unlock_bh(&flow_lock);
        return;
    }

    e->key = *k;
    e->expires_jiffies = jiffies + (ALLOW_TTL_SEC * HZ);
    hash_add(flow_ht, &e->hnode, h);

    spin_unlock_bh(&flow_lock);
}

static void flow_gc(struct timer_list *t)
{
    int bkt;
    struct flow_entry *e;
    struct hlist_node *tmp;

    spin_lock_bh(&flow_lock);
    hash_for_each_safe(flow_ht, bkt, tmp, e, hnode) {
        if (time_after_eq(jiffies, e->expires_jiffies)) {
            hash_del(&e->hnode);
            kfree(e);
        }
    }
    spin_unlock_bh(&flow_lock);

    mod_timer(&gc_timer, jiffies + (FLOW_GC_INTERVAL_SEC * HZ));
}

// -------------------- Demo auth verify --------------------
// Replace this with real crypto (HMAC/Ed25519) and anti-replay.
static bool verify_auth(const struct spa_msg *m, __be32 src_ip)
{
    // Demo tag = secret ^ src_ip ^ dst_port ^ ts_sec ^ magic ^ version
    // NOT SECURE, just a placeholder to show where signature check goes.
    u64 ts = be64_to_cpu(m->ts_sec);
    u64 tag = be64_to_cpu(m->tag);

    u64 expect = DEMO_SECRET;
    expect ^= (u64)be32_to_cpu(src_ip);
    expect ^= (u64)be16_to_cpu(m->dst_port);
    expect ^= ts;
    expect ^= (u64)be32_to_cpu(m->magic);
    expect ^= (u64)be16_to_cpu(m->version);

    return tag == expect;
}

// -------------------- Netfilter hook --------------------
static unsigned int fw_hook(void *priv,
                            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct iphdr *iph;
    u8 proto;
    __be32 saddr, daddr;

    if (!skb)
        return NF_ACCEPT;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    proto = iph->protocol;
    saddr = iph->saddr;
    daddr = iph->daddr;

    // Handle UDP
    if (proto == IPPROTO_UDP) {
        struct udphdr *udph;
        unsigned int ihl = iph->ihl * 4;

        if (!pskb_may_pull(skb, ihl + sizeof(struct udphdr)))
            return NF_ACCEPT;

        udph = (struct udphdr *)((u8 *)iph + ihl);

        // AUTH packets to AUTH_PORT
        if (ntohs(udph->dest) == AUTH_PORT) {
            struct spa_msg msg;
            unsigned int ulen = ntohs(udph->len);
            unsigned int payload_len = (ulen >= sizeof(struct udphdr)) ? (ulen - sizeof(struct udphdr)) : 0;
            u8 *payload = (u8 *)udph + sizeof(struct udphdr);

            if (payload_len < sizeof(struct spa_msg)) {
                printk(KERN_INFO "fwk: AUTH too small from %pI4\n", &saddr);
                return NF_DROP;
            }

            // copy to aligned stack struct (safe even if payload unaligned)
            memcpy(&msg, payload, sizeof(msg));

            if (msg.magic != cpu_to_be32(SPA_MAGIC) || msg.version != cpu_to_be16(1)) {
                printk(KERN_INFO "fwk: AUTH bad magic/version from %pI4\n", &saddr);
                return NF_DROP;
            }

            // Verify signature/tag
            if (!verify_auth(&msg, saddr)) {
                printk(KERN_INFO "fwk: AUTH FAILED from %pI4\n", &saddr);
                return NF_DROP;
            }

            // Allow flow to requested port (typically PROTECTED_PORT)
            {
                struct flow_key k = {
                    .src_ip = saddr,
                    .dst_ip = daddr, // server IP as seen in packet
                    .dst_port = msg.dst_port,
                    .proto = IPPROTO_UDP
                };
                flow_allow(&k);
                printk(KERN_INFO "fwk: AUTH OK allow UDP %pI4 -> port %u for %us\n",
                       &saddr, (unsigned)be16_to_cpu(msg.dst_port), ALLOW_TTL_SEC);
            }

            return NF_ACCEPT;
        }

        // PROTECTED_PORT traffic (UDP) allowed only if flow exists
        if (ntohs(udph->dest) == PROTECTED_PORT) {
            struct flow_key k = {
                .src_ip = saddr,
                .dst_ip = daddr,
                .dst_port = udph->dest,
                .proto = IPPROTO_UDP
            };

            if (flow_is_allowed(&k)) {
                return NF_ACCEPT;
            } else {
                printk(KERN_INFO "fwk: DROP UDP %pI4 -> port %u (no auth)\n",
                       &saddr, (unsigned)PROTECTED_PORT);
                return NF_DROP;
            }
        }

        return NF_ACCEPT;
    }

    // Handle TCP (optional, same gating concept)
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph;
        unsigned int ihl = iph->ihl * 4;

        if (!pskb_may_pull(skb, ihl + sizeof(struct tcphdr)))
            return NF_ACCEPT;

        tcph = (struct tcphdr *)((u8 *)iph + ihl);

        if (ntohs(tcph->dest) == PROTECTED_PORT) {
            struct flow_key k = {
                .src_ip = saddr,
                .dst_ip = daddr,
                .dst_port = tcph->dest,
                .proto = IPPROTO_TCP
            };

            if (flow_is_allowed(&k)) {
                return NF_ACCEPT;
            } else {
                printk(KERN_INFO "fwk: DROP TCP %pI4 -> port %u (no auth)\n",
                       &saddr, (unsigned)PROTECTED_PORT);
                return NF_DROP;
            }
        }

        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

// -------------------- Module init/exit --------------------
static int __init fwk_init(void)
{
    hash_init(flow_ht);

    nfho.hook = fw_hook;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho) != 0) {
        printk(KERN_ERR "fwk: failed to register netfilter hook\n");
        return -1;
    }

    timer_setup(&gc_timer, flow_gc, 0);
    mod_timer(&gc_timer, jiffies + (FLOW_GC_INTERVAL_SEC * HZ));

    printk(KERN_INFO "fwk: loaded AUTH_PORT=%u PROTECTED_PORT=%u TTL=%us\n",
           (unsigned)AUTH_PORT, (unsigned)PROTECTED_PORT, (unsigned)ALLOW_TTL_SEC);

    return 0;
}

static void __exit fwk_exit(void)
{
    int bkt;
    struct flow_entry *e;
    struct hlist_node *tmp;

    del_timer_sync(&gc_timer);
    nf_unregister_net_hook(&init_net, &nfho);

    spin_lock_bh(&flow_lock);
    hash_for_each_safe(flow_ht, bkt, tmp, e, hnode) {
        hash_del(&e->hnode);
        kfree(e);
    }
    spin_unlock_bh(&flow_lock);

    printk(KERN_INFO "fwk: unloaded\n");
}

module_init(fwk_init);
module_exit(fwk_exit);
