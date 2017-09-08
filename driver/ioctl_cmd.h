/* * File:	ioctl_cmd.h
 *
 * Descriptor:
 *
 *
 * Version History:
 *
 *	2017.04.19	Created by Leexy.
 *
 */

#ifndef _ECARD_IOCTL_CMD_H
#define _ECARD_IOCTL_CMD_H

#define ECARD_IOC_MAGIC	'C'

#define IO_RESET		0x00
#define IO_CMD			0x10
#define IO_DEBUG		0x20
#define IO_LOOPBACK_EX		0x21

#define ECARD_IOC_MAXNR         IO_LOOPBACK_EX

#define TO_LOOPBACK		0x8000
#define TO_FPGA			0x0000

#pragma pack(push,1)

typedef struct io_sync_req
{
	u16		in0Len ;
	u16		in1Len ;
	u16		in2Len ;
	u16		out0Len ;
	u16		out1Len ;
	u16		out2Len ;
	u8		*in0Dat ;
	u8		*in1Dat ;
	u8		*in2Dat ;
	u8		*out0Dat ;
	u8		*out1Dat ;
	u8		*out2Dat ;

	u16		flags ;	/* Bit 15   -- 1/0 TO_LOOPBACK/TO_FPGA */
                                /* Bit 14:3 -- reserve */
                                /* Bit 2:0  -- Channel, #0~#7 */
    u8      errcode ;
    u8      reserve ;
} IoSyncReq ;

typedef IoSyncReq   IoKernelReq ;

typedef struct loopback_ex_req
{
	u16		in0Len ;
	u16		in1Len ;
	u16		in2Len ;
	u16		out0Len ;
	u16		out1Len ;
	u16		out2Len ;
	u16		in0Off ;
	u16		in1Off ;
	u16		in2Off ;
	u16		out0Off ;
	u16		out1Off ;
	u16		out2Off ;
	u8		*in0Dat ;
	u8		*in1Dat ;
	u8		*in2Dat ;
	u8		*out0Dat ;
	u8		*out1Dat ;
	u8		*out2Dat ;

	u16		flags ;	/* Bit 15   -- 1/0 TO_LOOPBACK/TO_FPGA */
                                /* Bit 14:3 -- reserve */
                                /* Bit 2:0  -- Channel, #0~#7 */
    u8      errcode ;
    u8      reserve ;
} LoopbackExReq ;

#pragma pack(pop)

#define ECARD_IOC_TRESET		_IO(ECARD_IOC_MAGIC, IO_RESET)
#define ECARD_IOC_TDEBUG		_IO(ECARD_IOC_MAGIC, IO_DEBUG)
#define ECARD_IOC_CMD			_IOWR(ECARD_IOC_MAGIC,IO_CMD,IoSyncReq)
#define ECARD_IOC_LOOPBACK_EX	_IOWR(ECARD_IOC_MAGIC,IO_LOOPBACK_EX,LoopbackExReq)

#endif

