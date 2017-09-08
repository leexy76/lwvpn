/* 
 * File: leevpn.c
 *
 * Description:
 *      Main program of lwvpn (Light-weight VPN).
 *      
 *      A very simple VPN module than drop packet, encrypt packet or 
 *  decrypt packet, based on their source IP address & dest IP address.
 *
 *      Written by Leexy, @ 20170905.
 *      
 * Version History:
 *  2017.09.05
 *
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#include "leevpn.h"
#include "sdr_k_api.h"

#ifdef CONFIG_PROC_FS
#include "leevpn_proc.h"
#endif

/* Various flags used by the module */
/* This flag makes sure that only one instance of the lwvpn device
 * can be in use at any time. */
static int lwvpn_ctrl_in_use = 0 ;

/* Control device major number */
static int major = 0 ;

/* This struct will describe our hook procedure */
static struct nf_hook_ops  nfvpn ;

/* Module statistics structure */
struct lwvpn_stats  g_stats ; /* = { 0, 0, 0, 0 } ; */

/* Module vpn policy list */
struct list_head    g_rule_list ;
rwlock_t            g_rule_rwlock ;

/* Default Rule */
struct lwvpn_rule   default_rule ;

struct cdev cdev_m ;

static int add_rule(struct lwvpn_rule *new_rule)
{
    struct lwvpn_rule *rule;
    unsigned long flags ;
    
    write_lock_irqsave(&g_rule_rwlock, flags) ;

    list_for_each_entry(rule, &g_rule_list, list)
    {
        if(new_rule->policy.priority <= rule->policy.priority)
            break ;
    }
    list_add_tail(&new_rule->list, &rule->list) ;

    write_unlock_irqrestore(&g_rule_rwlock, flags) ;

    return 0 ;
}

static void del_rule(uint32 snet, uint32 dnet)
{
    struct lwvpn_rule *rule, *tmp ;
    unsigned long flags ;
    
    if((snet==0) && (dnet==0))
        return ;

    write_lock_irqsave(&g_rule_rwlock, flags) ;

    list_for_each_entry_safe(rule, tmp, &g_rule_list, list)
    {
        if((snet == rule->policy.snet) && (dnet == rule->policy.dnet))
        {
            list_del(&rule->list) ;
            kfree(rule) ;
        }
    }

    write_unlock_irqrestore(&g_rule_rwlock, flags) ;
}

static void clr_rule(void)
{
    struct lwvpn_rule *rule, *tmp ;
    unsigned long flags ;
     
    write_lock_irqsave(&g_rule_rwlock, flags) ;

    list_for_each_entry_safe(rule, tmp, &g_rule_list, list)
    {
        if(rule != &default_rule) {
            list_del(&rule->list) ;
            kfree(rule) ;
        }
    }

    write_unlock_irqrestore(&g_rule_rwlock, flags) ;
}

#if 0
int inet_addr(char *str, uint32 net, uint32 mask)
{
    char *pm, *pn ;
    int i1,i2,i3,i4,m1,m2,m3,m4;
    pm = (char *)&mask ;
    pn = (char *)&net ;

	sscanf(str,"%d.%d.%d.%d/%d.%d.%d.%d", 
            &i1,&i2,&i3,&i4,&m1,&m2,&m3,&m4) ;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    *pn = (uint8)i1;
    *(pn+1) = (uint8)i2;
    *(pn+2) = (uint8)i3;
    *(pn+3) = (uint8)i4;
    *pm = (uint8)m1;
    *(pm+1) = (uint8)m2;
    *(pm+2) = (uint8)m3;
    *(pm+3) = (uint8)m4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    *pn = (uint8)i4;
    *(pn+1) = (uint8)i3;
    *(pn+2) = (uint8)i2;
    *(pn+3) = (uint8)i1;
    *pm = (uint8)m4;
    *(pm+1) = (uint8)m3;
    *(pm+2) = (uint8)m2;
    *(pm+3) = (uint8)m1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return 0 ;
}
#endif

static void dump_iph(struct iphdr *iph)
{
	printk("ihl: %x, version: %x, tos: %02x, tot_len: %04x\n", 
		iph->ihl, iph->version, iph->tos, ntohs(iph->tot_len)) ;
	printk("id: %04x, frag_off: %04x\n", 
		ntohs(iph->id), ntohs(iph->frag_off)) ;
	printk("ttl: %02x, proto: %02x, check: %04x\n", 
		iph->ttl, iph->ttl, ntohs(iph->check)) ;
	printk("saddr: %08x\n", ntohl(iph->saddr)) ;
	printk("daddr: %08x\n", ntohl(iph->daddr)) ;
}

static struct lwvpn_rule *find_rule(uint32 saddr, uint32 daddr)
{
    struct lwvpn_rule *rule ;
    unsigned long flags ;
     
    read_lock_irqsave(&g_rule_rwlock, flags) ;

    list_for_each_entry(rule, &g_rule_list, list)
    {
        if((saddr & rule->policy.smask) != rule->policy.snet)
            continue ;
        if((daddr & rule->policy.dmask) != rule->policy.dnet)
            continue ;

        read_unlock_irqrestore(&g_rule_rwlock, flags) ;
        return rule ;
    }

    read_unlock_irqrestore(&g_rule_rwlock, flags) ;
    return NULL ;
}

struct CbParam 
{
    int (*okfn)(struct sk_buff *) ;
    struct sk_buff      *skb ;
    int                 inlen ;
    int                 outlen ;
    struct lwvpn_stats  *pstats ;
} ;

void encrypt_skb_cb(int ret, void *param)
{
    struct CbParam *p = (struct CbParam *)param ;

    if(ret != SDR_OK)
    {
        //++p->pstats->pack_encrypt_err ;
        atomic64_add(1, &p->pstats->pack_encrypt_err) ;
    } else {
        //++p->pstats->pack_encrypted ;
        atomic64_add(1, &p->pstats->pack_encrypted) ;
        //p->pstats->byte_encrypted += p->outlen ;
        atomic64_add(p->outlen, &p->pstats->byte_encrypted) ;
    }

    p->okfn(p->skb) ;
    kfree(param) ;
}

int encrypt_skb(struct lwvpn_rule *rule, struct sk_buff *skb, int (*okfn)(struct sk_buff *)) 
{
    int len ;
    struct CbParam *param ;

    if(skb_is_nonlinear(skb)) {
        //++g_stats.nonlinear ;
        atomic64_add(1, &g_stats.nonlinear) ;
        okfn(skb) ; 
        return 0;
    }
    
    len = skb->len & ~0x0f ;
    
    if(len == 0) {
        //++g_stats.toosmall ;
        atomic64_add(1, &g_stats.toosmall) ;
        okfn(skb) ;
        return 0 ;
    }

    param = (struct CbParam *)kmalloc(sizeof(*param), GFP_KERNEL) ;
    if(param) {
        //++g_stats.outmem ;
        atomic64_add(1, &g_stats.outmem) ;
        okfn(skb) ;
        return 0 ;
    }

    param->okfn = okfn ;
    param->skb = skb ;
    param->inlen = len ;
    param->outlen= 0 ;
    param->pstats = &g_stats ;

    return SDF_ExternalEncrypt_Ex(
            0, 
            rule->policy.key, 
            SGD_SM4_ECB, 
            rule->policy.iv, 
            skb->data,
            len ,
            skb->data,
            &param->outlen,
            encrypt_skb_cb,
            param
            ) ;
}

void decrypt_skb_cb(int ret, void *param)
{
    struct CbParam *p = (struct CbParam *)param ;

    if(ret != SDR_OK)
    {
        //++p->pstats->pack_decrypt_err ;
        atomic64_add(1, &p->pstats->pack_decrypt_err) ;
    } else {
        //++p->pstats->pack_decrypted ;
        atomic64_add(1, &p->pstats->pack_decrypted) ;
        //p->pstats->byte_decrypted += p->outlen ;
        atomic64_add(p->outlen, &p->pstats->byte_decrypted) ;
    }

    p->okfn(p->skb) ;
    kfree(param) ;
}

int decrypt_skb(struct lwvpn_rule *rule, struct sk_buff *skb, int (*okfn)(struct sk_buff *)) 
{
    int len ;
    struct CbParam *param ;

    if(skb_is_nonlinear(skb)) {
        //++g_stats.nonlinear ;
        atomic64_add(1, &g_stats.nonlinear) ;
        okfn(skb) ; 
        return 0;
    }
    
    len = skb->len & ~0x0f ;
    
    if(len == 0) {
        //++g_stats.toosmall ;
        atomic64_add(1, &g_stats.toosmall) ;
        okfn(skb) ;
        return 0 ;
    }

    param = (struct CbParam *)kmalloc(sizeof(*param), GFP_KERNEL) ;
    if(param) {
        //++g_stats.outmem ;
        atomic64_add(1, &g_stats.outmem) ;
        okfn(skb) ;
        return 0 ;
    }

    param->okfn = okfn ;
    param->skb = skb ;
    param->inlen = len ;
    param->outlen= 0 ;
    param->pstats = &g_stats ;

    return SDF_ExternalDecrypt_Ex(
            0, 
            rule->policy.key, 
            SGD_SM4_ECB, 
            rule->policy.iv, 
            skb->data,
            len ,
            skb->data,
            &param->outlen,
            decrypt_skb_cb,
            param
            ) ;
}

unsigned int lwvpn_func(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sk ;
	struct iphdr *iph ;
    struct lwvpn_rule *rule ;
    uint32  ret = NF_DROP ;

	sk = skb ;
	iph = ip_hdr(sk);

    rule = find_rule(iph->saddr, iph->daddr) ;
    if(rule == NULL) {
        return NF_DROP ;
    } 

    switch(rule->policy.action)
    {
    case V_ENCRY:
        encrypt_skb(rule, skb, okfn) ;
        ret = NF_STOLEN ;
        break ;

    case V_DECRY:
        decrypt_skb(rule, skb, okfn) ;
        ret = NF_STOLEN ;
        break ;

    case V_PASS:
        ret = NF_ACCEPT ;
        break ;

    case V_DROP:
        ret = NF_DROP ;
        break ;
    }

	return ret ;
}

static long lwvpn_compat_ioctl(struct file *filp,unsigned int cmd,unsigned long arg) 
{
    long err = 0 ;

    if(_IOC_TYPE(cmd) != LWVPN_IOC_MAGIC) {
        LWV_INFO("_IOC_TYPE(cmd) %08x, LWVPN_IOC_MAGIC %08x\n", _IOC_TYPE(cmd), LWVPN_IOC_MAGIC) ;
        return -ENOTTY ;
    }
    if(_IOC_NR(cmd) > LWVPN_IOC_MAXNR) {
        LWV_INFO("_IOC_NR(cmd) %08x, LWVPN_IOC_MAXNR %08x\n", _IOC_NR(cmd), LWVPN_IOC_MAGIC) ;
        return -ENOTTY ;
    }

    if(_IOC_DIR(cmd) & _IOC_READ) 
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd)) ;

    if(!err && (_IOC_DIR(cmd) & _IOC_WRITE))
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd)) ;

    if(err)
        return -EFAULT ;

    switch(cmd) {
    case LWVPN_GET_VERS:
        LWV_INFO("LWVPN_GET_VERS\n") ;
        err = put_user(LWVPN_VERS, (uint32 __user *)arg) ;
        break ;

    case LWVPN_ADD_RULE:
        LWV_INFO("LWVPN_ADD_RULE\n") ;
        {
            struct lwvpn_rule *rule ;
            rule = kmalloc(sizeof(*rule), GFP_KERNEL) ;
            if(rule == NULL) {
                err = -EFAULT ;
            } else if(copy_from_user(&rule->policy, (char __user *)arg, sizeof(struct lwvpn_policy))) {
                    kfree(rule) ;
                    err = -EFAULT ;
            } else {
                add_rule(rule) ;
            }
        }
        break ;

    case LWVPN_DEL_RULE:
        LWV_INFO("LWVPN_DEL_RULE\n") ;
        {
            IoDelRuleReq req ;
            if(copy_from_user(&req, (char __user *)arg, sizeof(req))) {
                err = -EFAULT ;
            } else {
                del_rule(req.snet, req.dnet) ;
            }
        }
        break ;

    case LWVPN_CLR_RULE:
        LWV_INFO("LWVPN_CLR_RULE\n") ;
        clr_rule() ;
        break ;

    default:
        LWV_INFO("Unknown cmd: %08x\n", cmd) ;
        err = -EINVAL ;
        break ;
    }

    return err ;
}

static long lwvpn_unlocked_ioctl(struct file *flip,unsigned int cmd,unsigned long arg) 
{
    return lwvpn_compat_ioctl(flip, cmd, arg) ;
}

static int lwvpn_open(struct inode *inode, struct file *file)
{
    if(lwvpn_ctrl_in_use) {
        return -EBUSY ;
    } else {
        lwvpn_ctrl_in_use++ ;
    }
    return 0 ;
}

static int lwvpn_release(struct inode *inode, struct file *file)
{
    lwvpn_ctrl_in_use ^= lwvpn_ctrl_in_use ;
    return 0 ;
}

/* 
 * This is the interface device's file operations structure 
 */
static struct file_operations lwvpn_fops = {
    .owner = THIS_MODULE ,
    .unlocked_ioctl = lwvpn_unlocked_ioctl ,
    .compat_ioctl = lwvpn_compat_ioctl ,
    .open = lwvpn_open ,
    .release = lwvpn_release,
} ;

static int __init init_lwvpn_m(void)
{
    int result, err ;
    dev_t devno, devno_m ;

    /* Clean LWVPN stats */
    //memset(&g_stats, 0, sizeof(g_stats)) ;
    atomic64_set(&g_stats.pack_dropped,     0) ;
    atomic64_set(&g_stats.pack_passed,      0) ;
    atomic64_set(&g_stats.pack_encrypted,   0) ;
    atomic64_set(&g_stats.byte_encrypted,   0) ;
    atomic64_set(&g_stats.pack_encrypt_err, 0) ;
    atomic64_set(&g_stats.pack_decrypted,   0) ;
    atomic64_set(&g_stats.byte_decrypted,   0) ;
    atomic64_set(&g_stats.pack_decrypt_err, 0) ;
    atomic64_set(&g_stats.nonlinear,        0) ;
    atomic64_set(&g_stats.toosmall,         0) ;
    atomic64_set(&g_stats.outmem,           0) ;

    /* Initial LWVPN rules */
    rwlock_init(&g_rule_rwlock) ;
    INIT_LIST_HEAD(&g_rule_list) ;

    /* Set default rule */
    memset(&default_rule, 0, sizeof(struct lwvpn_rule)) ;
    default_rule.policy.action = V_DROP ;
    default_rule.policy.priority = 255 ;
    list_add_tail(&default_rule.list, &g_rule_list) ;

    /* Register the control device, /dev/lwvpn */
    result = alloc_chrdev_region(&devno, 0, 1, LWVPN_NAME) ;
    major = MAJOR(devno) ;

    if(result < 0)
        return result ;

    devno_m = MKDEV(major, 0);
    printk("major is %d\n", MAJOR(devno_m));
    printk("minor is %d\n", MINOR(devno_m));

    cdev_init(&cdev_m, &lwvpn_fops) ;
    cdev_m.owner = THIS_MODULE ;
    cdev_m.ops = &lwvpn_fops ;
    err = cdev_add(&cdev_m, devno_m, 1) ;
    if(err != 0) {
        printk("cdev_add error\n");
        return -1 ;
    }
 
    lwvpn_ctrl_in_use ^= lwvpn_ctrl_in_use ;
    printk("LWVPN: Control device successfully registered.\n") ;

    /* Now register the network hooks */
	nfvpn.hook = lwvpn_func ;
	nfvpn.hooknum = NF_INET_FORWARD ;     /* IP Forward */
	nfvpn.pf = PF_INET ;                  /* IPv4 protocol hook */
	nfvpn.priority = NF_IP_PRI_FIRST ;    /* Hook to come first */

    /* And register... */
    nf_register_hook(&nfvpn) ;

#ifdef CONFIG_PROC_FS
    lwvpn_create_proc_dir() ;
    lwvpn_create_dev_dir() ;
#endif
    printk("LWVPN: Network hooks successfully installed.\n") ;

    printk("LWVPN: Module installation successful.\n") ;

    return 0;
}

static void __exit cleanup_lwvpn_m(void)
{
    /* Remove ipv4 hook */
    nf_unregister_hook(&nfvpn) ;

    /* Now unregister control device */
    cdev_del(&cdev_m) ;
    unregister_chrdev_region(MKDEV(major,0), 1) ;

#ifdef CONFIG_PROC_FS
    lwvpn_remove_dev_dir() ;
    lwvpn_destroy_proc_dir() ;
#endif
    printk("LeeVpn: Removal of module successful.\n") ;
}

module_init(init_lwvpn_m) ;
module_exit(cleanup_lwvpn_m) ;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leexy");
