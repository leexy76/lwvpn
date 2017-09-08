/* 
 * File:	leevpn_proc.c
 *
 * Descriptor:
 *
 *
 * Version History:
 *
 *	2017.09.06	Created by Leexy, for LW-VPN (Light-wight VPN) .
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/rtc.h>
#include <linux/spinlock.h>
#include <linux/bcd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include <linux/pci_regs.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#include <asm/system.h>
#endif

//#include "utils.h"
//#include "dbg_utils.h"
#include "leevpn.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)

static struct proc_dir_entry *lwvpn_proc_root = NULL;
static int	LWVPN_FILE_PERM = 0644 ;

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)

static int  LWVPN_PROC_PERM = 0555 ;

#define proc_mkdir(name, proc_root) \
        create_proc_entry(name, S_IFDIR|ECARD_PROC_PERM, proc_root)

#define PDE_DATA(x) PDE(x)->data

#endif

extern struct lwvpn_stats  g_stats ;
extern struct list_head    g_rule_list ;

/*
 * lwvpn stat.
 *---------------------------------------------------
 */
#ifdef CONFIG_64BIT	
#define SHOW_STATIS(seq,st,field) \
    seq_printf((seq), "%18s : %ld\n", #field, atomic64_read(&((st)->field)))
 
#else 
#define SHOW_STATIS(seq,st,field) \
    seq_printf((seq), "%18s : %lld\n", #field, atomic64_read(&((st)->field)))
#endif
	

static int lwvpn_stat_show(
	struct seq_file	*seq,
	void   *v
	)
{
    SHOW_STATIS(seq,&g_stats, pack_dropped) ;
    SHOW_STATIS(seq,&g_stats, pack_passed) ;
    SHOW_STATIS(seq,&g_stats, pack_encrypted) ;
    SHOW_STATIS(seq,&g_stats, byte_encrypted) ;
    SHOW_STATIS(seq,&g_stats, pack_encrypt_err) ;
    SHOW_STATIS(seq,&g_stats, pack_decrypted) ;
    SHOW_STATIS(seq,&g_stats, byte_decrypted) ;
    SHOW_STATIS(seq,&g_stats, pack_decrypt_err) ;
    SHOW_STATIS(seq,&g_stats, nonlinear) ;
    SHOW_STATIS(seq,&g_stats, toosmall) ;
    SHOW_STATIS(seq,&g_stats, outmem) ;
    
	return 0 ;
}

static int lwvpn_stat_proc_open(
	struct inode    *inode ,
	struct file     *filp
	)
{
	return single_open(filp, lwvpn_stat_show, PDE_DATA(inode)) ;
}
	
static const struct file_operations lwvpn_stat_ops = {
	.owner	= THIS_MODULE ,
	.open	= lwvpn_stat_proc_open ,
	.read	= seq_read ,
	.llseek	= seq_lseek ,
	.release	= single_release,
} ;

/*
 * lwvpn rule info
 *---------------------------------------------------
 */
static struct lwvpn_rule *rule_iter = NULL ; 

static void *policy_seq_start(struct seq_file *seq, loff_t *pos)
{
	if ( *pos == 0 ) {
		rule_iter = list_first_entry_or_null(&g_rule_list, struct lwvpn_rule, list) ;
	}

	if ( &rule_iter->list == &g_rule_list )
		return NULL ;
	else
		return (void *)(rule_iter->list.next) ;
}

static void *policy_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if ( &rule_iter->list == &g_rule_list )
		return NULL ;
	else
		return (void *)(rule_iter->list.next) ;
}

static char *action_str(uint8 action)
{
    switch(action)
    {
    case V_DROP:
        return "DROP" ;
    case V_ENCRY:
        return "ENCRY" ;
    case V_DECRY:
        return "DECRY" ;
    case V_PASS:
        return "PASS" ;
    default:
        break ;
    }
    return "<UNKNOWN>" ;
}

static int policy_seq_show(struct seq_file *seq, void *v)
{
	int	    count = 0, i ;
    struct lwvpn_policy *p ;

    list_for_each_entry_continue(rule_iter, &g_rule_list, list)
    {
        p = &rule_iter->policy ;
		seq_printf(seq, "%d.%d.%d.%d/%d.%d.%d.%d --> %d.%d.%d.%d/%d.%d.%d.%d\n", 
                (p->snet >> 24) & 0xFF,
                (p->snet >> 16) & 0xFF,
                (p->snet >> 8) & 0xFF,
                p->snet & 0xFF,
                (p->smask >> 24) & 0xFF,
                (p->smask >> 16) & 0xFF,
                (p->smask >> 8) & 0xFF,
                p->smask & 0xFF,
                (p->dnet >> 24) & 0xFF,
                (p->dnet >> 16) & 0xFF,
                (p->dnet >> 8) & 0xFF,
                p->dnet & 0xFF,
                (p->dmask >> 24) & 0xFF,
                (p->dmask >> 16) & 0xFF,
                (p->dmask >> 8) & 0xFF,
                p->dmask & 0xFF ) ;

        seq_printf(seq, "    %s %d\n",
                action_str(p->action), 
                p->priority ) ;

        seq_printf(seq, "    ");
        for(i=0; i<16; ++i) {
            seq_printf(seq, "%02x", p->key[i]) ;
        }
        seq_printf(seq, "\n") ;
       
        seq_printf(seq, "    ");
        for(i=0; i<16; ++i) {
            seq_printf(seq, "%02x", p->iv[i]) ;
        }
        seq_printf(seq, "\n") ;
       
        if(++count >= 8)
            break ;
    }

	return 0;
}

static void policy_seq_stop(struct seq_file *seq, void *v)
{
	return ;
}

static struct seq_operations policy_seq_ops = {
	.start	= policy_seq_start ,
	.next	= policy_seq_next ,
	.stop	= policy_seq_stop ,
	.show	= policy_seq_show
} ;

static int lwvpn_policy_proc_open(
	struct inode	*inode ,
	struct file		*filp
	)
{
	int res = -ENOMEM;
	
	res = seq_open(filp, &policy_seq_ops) ;
	if (!res)
	{
		((struct seq_file *)filp->private_data)->private = PDE_DATA(inode) ;
	}
		
	return res ;
}
	
static const struct file_operations lwvpn_policy_ops = {
	.owner	= THIS_MODULE ,
	.open	= lwvpn_policy_proc_open ,
	.read	= seq_read ,
	.llseek	= seq_lseek ,
	.release	= seq_release,
} ;

/*
 * lwvpn proc #
 *---------------------------------------------------
 */
void lwvpn_create_dev_dir(void)
{
	//struct proc_dir_entry	*entry ;
	
    if(lwvpn_proc_root == NULL)
        return ;

    proc_create_data("policy",
                    S_IFREG | (S_IRUGO & LWVPN_FILE_PERM),
                    lwvpn_proc_root,
                    &lwvpn_policy_ops, NULL) ;

    proc_create_data("stat", 
					S_IFREG | (S_IRUGO & LWVPN_FILE_PERM),
					lwvpn_proc_root, 
					&lwvpn_stat_ops, NULL) ;
}

void lwvpn_remove_dev_dir(void)
{
    if(lwvpn_proc_root == NULL)
        return ;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    proc_remove(lwvpn_proc_root) ;
#else
	remove_proc_entry("stat", ecard_proc_root) ;
	remove_proc_entry("policy", ecard_proc_root) ;
#endif
}

/*
 * ROOT of LW-VPN proc filesystem
 *---------------------------------------------------
 */

/* Create the bonding directory under /proc , if doesn't exist yet.
 * Caller must hold rtnl_lock.
 */
void lwvpn_create_proc_dir(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
    //struct proc_dir_entry *entry  ;

    lwvpn_proc_root = proc_mkdir(LWVPN_NAME, NULL);
    if (lwvpn_proc_root)
    {
//#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        lwvpn_proc_root->owner = THIS_MODULE;
#endif
    }
    else
    {
        printk(KERN_WARNING LWVPN_NAME
            ": Warning: cannot create /proc/%s\n",
            LWVPN_NAME);
    }
#endif
}

/* Destroy the bonding directory under /proc , if empty.
 * Caller must hold rtnl_lock.
 */
void lwvpn_destroy_proc_dir(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
    proc_remove(lwvpn_proc_root) ;
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
    struct proc_dir_entry *de;

    if (!lwvpn_proc_root) {
        return;
    }

    /* verify that the /proc dir is empty */
    for (de = lwvpn_proc_root->subdir; de; de = de->next)
    {
        /* ignore . and .. */
        if (*(de->name) != '.')
        {
            remove_proc_entry(de->name, lwvpn_proc_root);
        }
    }

    remove_proc_entry(LWVPN_NAME, NULL) ;
#endif
}

