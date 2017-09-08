/* 
 * File:    sdr_errno.h
 *
 * Descriptor:
 *
 *
 * Version History:
 *
 *  2017.07.19  Created by Leexy.
 *
 */
#ifndef SDR_ERR_CODE_H
#define SDR_ERR_CODE_H

#define SDR_OK                  0x0
#define SDR_BASE                0x01000000
#define SDR_UNKNOWERR           (SDR_BASE+0x01)
#define SDR_NOTSUPPORT          (SDR_BASE+0x02)
#define SDR_COMMFAIL            (SDR_BASE+0x03)
#define SDR_HARDFAIL            (SDR_BASE+0x04)
#define SDR_OPENDEVICE          (SDR_BASE+0x05)
#define SDR_OPENSESSION         (SDR_BASE+0x06)
#define SDR_PARDENY             (SDR_BASE+0x07)
#define SDR_KEYNOTEXIST         (SDR_BASE+0x08)
#define SDR_ALGNOTSUPPORT       (SDR_BASE+0x09)
#define SDR_ALGMODNOTSUPPORT    (SDR_BASE+0x0A)
#define SDR_PKOPERR             (SDR_BASE+0x0B)
#define SDR_SKOPERR             (SDR_BASE+0x0C)
#define SDR_SIGNERR             (SDR_BASE+0x0D)
#define SDR_VERIFYERR           (SDR_BASE+0x0E)
#define SDR_SYMOPERR            (SDR_BASE+0x0F)
#define SDR_STEPERR             (SDR_BASE+0x10)
#define SDR_FILESIZEERR         (SDR_BASE+0x11)
#define SDR_FILENOEXIST         (SDR_BASE+0x12)
#define SDR_FILEOFSERR          (SDR_BASE+0x13)
#define SDR_KEYTYPEERR          (SDR_BASE+0x14)
#define SDR_KEYERR              (SDR_BASE+0x15)
#define SDR_ENCDATAERR          (SDR_BASE+0x16)
#define SDR_RANDERR             (SDR_BASE+0x17)
#define SDR_PRKRERR             (SDR_BASE+0x18)
#define SDR_MACERR              (SDR_BASE+0x19)
#define SDR_FILEEXISTS          (SDR_BASE+0x1A)
#define SDR_FILEWERR            (SDR_BASE+0x1B)
#define SDR_NOBUFFER            (SDR_BASE+0x1C)
#define SDR_INARGERR            (SDR_BASE+0x1D)
#define SDR_OUTARGERR           (SDR_BASE+0x1E)

/* Custom */
#define SDR_HASHERR             (SDR_BASE+0x10000)
#define SDR_HMACERR             (SDR_BASE+0x10000)

#endif

 
