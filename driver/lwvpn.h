/* 
 * File:    lwvpn.h
 *
 * Description:
 *
 *      Include file for the LW-VPN LKM.
 *
 *      A very simple VPN module than drop packet, encrypt packet or 
 *  decrypt packet, based on their source IP address & dest IP address.
 *
 *      Written by Leexy, @ 20170905
 *
 * Version History:
 *  2017.09.05  Created by Leexy.
 *
 */

#ifndef _LWVPN_H_
#define _LWVPN_H_

#define LWVPN_NAME     "LW-VPN"

/* Version of LWVPN */
#define LWVPN_VERS     0x0001  /* 0.1 */

typedef char        int8 ;
typedef short       int16 ;
typedef int         int32 ;
typedef long long   int64 ;

typedef unsigned char       uint8 ;
typedef unsigned short      uint16 ;
typedef unsigned int        uint32 ;
typedef unsigned long long  uint64 ;

#ifdef DEBUG

#define LWV_PRT(FMT, ...)       printk(KERN_ERR LWVPN_NAME " " FMT,## __VA_ARGS__)
#define LWV_INFO(FMT, ...)      printk(KERN_ERR LWVPN_NAME " " FMT,## __VA_ARGS__)
#define LWV_WARNING(FMT, ...)   printk(KERN_ERR LWVPN_NAME " " FMT,## __VA_ARGS__)
#define LWV_ERR(FMT, ...)       printk(KERN_ERR LWVPN_NAME " " FMT,## __VA_ARGS__)

#else

#define LWV_PRT(FMT, ...)
#define LWV_INFO(FMT, ...)
#define LWV_WARNING(FMT, ...)
#define LWV_ERR(FMT, ...)

#endif

#define V_DROP      0x00
#define V_ENCRY     0x01
#define V_DECRY     0x02
#define V_PASS      0x03

struct lwvpn_policy {
    uint32              snet ;
    uint32              smask ;
    uint32              dnet ;
    uint32              dmask ;
    uint8               action ;
    uint8               priority ;
    uint8               reserve[2] ;
    uint8               key[16] ;
    uint8               iv[16] ;
} ;

/* -------------------------------------------- */

#define LWVPN_IOC_MAGIC 'L'

#define IO_GET_VERS     0x00
#define IO_ADD_RULE     0x01
#define IO_DEL_RULE     0x02
#define IO_CLR_RULE     0x03

#define LWVPN_IOC_MAXNR IO_CLR_RULE

#pragma pack(push,1)

typedef struct io_get_vers
{
    uint32      version ;
} IoGetVers ;

typedef struct io_addrule_req
{
    struct lwvpn_policy policy ;
} IoAddRuleReq ;

typedef struct io_delrule_req
{
    uint32  snet ;
    uint32  dnet ;
} IoDelRuleReq ;

#pragma pack(pop)

#define LWVPN_GET_VERS      _IOR(LWVPN_IOC_MAGIC, IO_GET_VERS, IoGetVers)
#define LWVPN_CLR_RULE      _IO(LWVPN_IOC_MAGIC, IO_CLR_RULE)
#define LWVPN_ADD_RULE      _IOW(LWVPN_IOC_MAGIC, IO_ADD_RULE, IoAddRuleReq)
#define LWVPN_DEL_RULE      _IOW(LWVPN_IOC_MAGIC, IO_DEL_RULE, IoDelRuleReq)

#endif

