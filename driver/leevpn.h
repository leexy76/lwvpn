/* 
 * File:    leevpn.h
 *
 * Description:
 *
 *      Include file for the Lee VPN LKM.
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

#ifndef _LEE_VPN_H_
#define _LEE_VPN_H_

#include "lwvpn.h"

struct lwvpn_rule {
    struct list_head    list ;
    struct lwvpn_policy policy ;
} ;

/* Statistics structure for LWVPN */
struct lwvpn_stats {
    atomic64_t  pack_dropped ;
    atomic64_t  pack_passed ;
    atomic64_t  pack_encrypted ;
    atomic64_t  byte_encrypted ;
    atomic64_t  pack_encrypt_err ;
    atomic64_t  pack_decrypted ;
    atomic64_t  byte_decrypted ;
    atomic64_t  pack_decrypt_err ;
    atomic64_t  nonlinear ;
    atomic64_t  toosmall ;
    atomic64_t  outmem ;
/*
    uint64  pack_dropped ;
    uint64  pack_passed ;
    uint64  pack_encrypted ;
    uint64  byte_encrypted ;
    uint64  pack_encrypt_err ;
    uint64  pack_decrypted ;
    uint64  byte_decrypted ;
    uint64  pack_decrypt_err ;
    uint64  nonlinear ;
    uint64  toosmall ;
    uint64  outmem ;
*/
} ;

extern struct lwvpn_stats  g_stats ;
extern struct list_head    g_rule_list ;

#endif
