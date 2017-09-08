/*
 * File:    sdr_k_api.h
 *
 * Description:
 *
 * Version History:
 *
 *  Ver 0.01    -- Created by Leexy, @ 20170907
 *
 */

#ifndef _SDR_KERNEL_API_H_
#define _SDR_KERNEL_API_H_

#include "sdr_errno.h"

#define SGD_SSX06_ECB           0x00001001
#define SGD_SSX06_CBC           0x00001002
#define SGD_SM4_ECB             0x00000401
#define SGD_SM4_CBC             0x00000402

int SDF_ExternalEncrypt_Ex(
            void *hSessionHandle,
            unsigned char *pucKey,
            unsigned int uiAlgID,
            unsigned char *pucIV,           /* in/out */
            unsigned char *pucData,
            unsigned int uiDataLength,
            unsigned char *pucEncData,      /* out */
            unsigned int *puiEncDataLength, /* out */
            void (*usr_cb)(int, void *),
            void *usr_cb_param
            ) ;

int SDF_ExternalDecrypt_Ex(
            void *hSessionHandle,
            unsigned char *pucKey,
            unsigned int uiAlgID,
            unsigned char *pucIV,           /* in/out */
            unsigned char *pucEncData,
            unsigned int uiEncDataLength,
            unsigned char *pucData,         /* out */
            unsigned int *puiDataLength,    /* out */
            void (*usr_cb)(int, void *),
            void *usr_cb_param
            ) ;

#endif

