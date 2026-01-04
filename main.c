/*
 * Zero-Trust Firewall – Linux Kernel Module
 *
 * Tento modul implementuje jednoduchý Zero-Trust firewall přímo v jádře Linuxu
 * pomocí Netfilter hooku. Výchozí politika je:
 *
 *   - VŠE ZAKÁZÁNO
 *   - Přístup na chráněný port je povolen pouze po předchozí autorizaci (AUTH)
 *   - Autorizace je časově omezená (TTL)
 *
 * Modul slouží jako referenční vzor (pattern) pro:
 *   - stavový firewall
 *   - Single Packet Authorization (SPA) koncept
 *   - dynamické povolování spojení
 */
#include <linux/module.h>     // Základní makra pro kernel modul
#include <linux/kernel.h>     // printk(), KERN_INFO, atd.
#include <linux/init.h>       // module_init / module_exit

#include <linux/netfilter.h>          // Netfilter core
#include <linux/netfilter_ipv4.h>     // IPv4 Netfilter hooky

#include <linux/ip.h>         // Struktura IP hlavičky (struct iphdr)
#include <linux/udp.h>        // UDP hlavička
#include <linux/tcp.h>        // TCP hlavička

#include <linux/hashtable.h>  // Kernel hash tabulka
#include <linux/spinlock.h>   // Spinlock pro synchronizaci
#include <linux/slab.h>       // kmalloc / kfree
#include <linux/timer.h>      // Kernel timer
#include <linux/jiffies.h>    // Čas v kernelu (jiffies)

/*
 * Metadata modulu – důležité pro kernel i distribuce
 */
MODULE_LICENSE("GPL");	// Nutné pro přístup k některým symbolům kernelu
MODULE_AUTHOR("Damian Zeleny");   // Autor modulu
MODULE_DESCRIPTION("Zero-Trust Firewall (Kernel)");
MODULE_VERSION("1.0");

// ============================================================================
// Konfigurace modulu (lze měnit při insmod)
// ============================================================================

/*
 * AUTH_PORT
 * ----------
 * UDP port, na který klient odešle autorizační paket.
 * Přijetím paketu na tento port firewall vytvoří dočasné povolení (flow).
 */
static ushort AUTH_PORT = 40000;

/*
 * PROTECTED_PORT
 * --------------
 * Port, který je chráněný firewall logikou.
 * Přístup je povolen pouze, pokud existuje platná autorizace.
 */
static ushort PROTECTED_PORT = 9000;

/*
 * ALLOW_TTL_SEC
 * -------------
 * Doba platnosti autorizace v sekundách.
 * Po vypršení je flow automaticky odstraněno.
 */
static uint   ALLOW_TTL_SEC = 30;

/*
 * Umožňuje změnu parametrů při načtení modulu:
 * insmod ztfw.ko AUTH_PORT=... PROTECTED_PORT=... ALLOW_TTL_SEC=...
 */
module_param(AUTH_PORT, ushort, 0644);
module_param(PROTECTED_PORT, ushort, 0644);
module_param(ALLOW_TTL_SEC, uint, 0644);

// ============================================================================
// Stavová tabulka (Flow Table)
// ============================================================================

/*
 * Počet bucketů hash tabulky = 2^FLOW_BITS
 * Vyšší hodnota = lepší výkon, vyšší paměťová náročnost
 */
#define FLOW_BITS 10

/*
 * Klíč flow – jednoznačně identifikuje povolené spojení
 *
 * Používá se zjednodušený 4-tuple:
 *   src_ip + dst_ip + dst_port + protocol
 */
struct flow_key
{
    __be32 src_ip;     // Zdrojová IP adresa
    __be32 dst_ip;     // Cílová IP adresa
    __be16 dst_port;   // Cílový port
    u8 proto;          // IPPROTO_TCP / IPPROTO_UDP
};

/*
 * Položka ve flow tabulce
 */
struct flow_entry 
{
     struct flow_key key;          // Identifikátor flow
    unsigned long expires;        // Čas expirace (v jiffies)
    struct hlist_node node;       // Uzlový prvek hash tabulky
};

/*
 * Hash tabulka všech povolených flow
 */
static DEFINE_HASHTABLE(flow_table, FLOW_BITS);

/*
 * Spinlock – chrání flow_table proti souběžnému přístupu
 * (Netfilter hook + GC timer běží paralelně)
 */
static DEFINE_SPINLOCK(flow_lock);

/*
 * Timer pro periodický úklid expirovaných flow
 */
static struct timer_list gc_timer;

// ============================================================================
// Pomocné funkce pro práci s flow
// ============================================================================

/*
 * Porovnání dvou flow klíčů
 */
static bool flow_match(struct flow_key *a, struct flow_key *b)
{
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

/*
 * Ověření, zda je flow povoleno a neexpiruje
 */
static bool flow_allowed(struct flow_key *key)
{
    struct flow_entry *e;
    bool ok = false;

    spin_lock_bh(&flow_lock);
    hash_for_each_possible(flow_table, e, node, (u32)key->src_ip) 
	{
        if (flow_match(&e->key, key) && time_before(jiffies, e->expires)) 
		{
            ok = true;
            break;
        }
    }
    spin_unlock_bh(&flow_lock);

    return ok;
}

/*
 * Přidání nové autorizované flow
 */
static void flow_add(struct flow_key *key)
{
    struct flow_entry *e;
	
	/*
    * GFP_ATOMIC – funkce může běžet v kontextu,
    * kde není dovoleno usínání
    */

    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (!e)
        return;

    e->key = *key;
    e->expires = jiffies + ALLOW_TTL_SEC * HZ;

    spin_lock_bh(&flow_lock);
    hash_add(flow_table, &e->node, (u32)key->src_ip);
    spin_unlock_bh(&flow_lock);
}

// ============================================================================
// Garbage Collection – úklid expirovaných flow
// ============================================================================

/*
 * Periodicky odstraňuje flow, kterým vypršel TTL
 */
static void flow_gc(struct timer_list *t)
{
    struct flow_entry *e;
    struct hlist_node *tmp;
    int bkt;

    spin_lock_bh(&flow_lock);
    hash_for_each_safe(flow_table, bkt, tmp, e, node) 
	{
        if (time_after(jiffies, e->expires)) 
		{
            hash_del(&e->node);
            kfree(e);
        }
    }
    spin_unlock_bh(&flow_lock);

	// Znovu naplánuj GC za 5 sekund
    mod_timer(&gc_timer, jiffies + 5 * HZ);
}

// ============================================================================
// Netfilter hook – hlavní firewall logika
// ============================================================================

/*
 * Funkce je volána pro každý paket procházející daným hookem
 */
static unsigned int fw_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct flow_key key;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

	// Naplnění flow klíče z IP hlavičky
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto  = iph->protocol;

    // ---------- UDP ----------
    if (iph->protocol == IPPROTO_UDP)
	{
        struct udphdr *udph;

        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*udph)))
            return NF_ACCEPT;

        udph = udp_hdr(skb);
        key.dst_port = udph->dest;

        // AUTH packet
        if (ntohs(udph->dest) == AUTH_PORT) 
		{
            flow_add(&key);
            printk(KERN_INFO "ztfw: AUTH OK from %pI4\n", &iph->saddr);
            return NF_ACCEPT;
        }

        // Protected port
        if (ntohs(udph->dest) == PROTECTED_PORT) 
		{
            if (flow_allowed(&key))
                return NF_ACCEPT;

            printk(KERN_INFO "ztfw: DROP UDP %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

    // ---------- TCP ----------
    if (iph->protocol == IPPROTO_TCP)
	{
        struct tcphdr *tcph;

        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(*tcph)))
            return NF_ACCEPT;

        tcph = tcp_hdr(skb);
        key.dst_port = tcph->dest;

        if (ntohs(tcph->dest) == PROTECTED_PORT) 
		{
            if (flow_allowed(&key))
                return NF_ACCEPT;

            printk(KERN_INFO "ztfw: DROP TCP %pI4\n", &iph->saddr);
            return NF_DROP;
        }
    }

	// Vše ostatní projde
    return NF_ACCEPT;
}

// ============================================================================
// Inicializace a uvolnění modulu
// ============================================================================
// ---------------- Init / Exit ----------------
static struct nf_hook_ops nfho;

/*
 * Načtení modulu
 */
static int __init fw_init(void)
{
    hash_init(flow_table);

    nfho.hook = fw_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;	// Paket hned po přijetí
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    timer_setup(&gc_timer, flow_gc, 0);
    mod_timer(&gc_timer, jiffies + 5 * HZ);

    printk(KERN_INFO "ztfw: loaded (AUTH_PORT=%u PROTECTED_PORT=%u TTL=%u)\n",
           AUTH_PORT, PROTECTED_PORT, ALLOW_TTL_SEC);

    return 0;
}

/*
 * Odstranění modulu
 */
static void __exit fw_exit(void)
{
    del_timer_sync(&gc_timer);
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "ztfw: unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
