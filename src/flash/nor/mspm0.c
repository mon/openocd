// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2023 by William Toohey                                  *
 *   will@mon.im	                                                       *
 ***************************************************************************/

/***************************************************************************
* MSPM0 flash is tested on MSPM0G3507
* It does *not* support password protected debug/erase functionality
* It does *not* support flash protection - a protected region will simply
*   fail to program
* It currently only supports MAIN memory. NONMAIN can be erased, but
*   not individually
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jtag/interface.h"
#include "imp.h"
#include <target/algorithm.h>
#include <target/arm_adi_v5.h>
#include <target/register.h>
#include <target/arm.h>
#include <target/cortex_m.h>

/* MSPM0 registers */
#define FACTORYREGION_BASE	0x41C40000
#define TRACEID				(FACTORYREGION_BASE + 0x000)
#define DEVICEID			(FACTORYREGION_BASE + 0x004)
#define USERID				(FACTORYREGION_BASE + 0x008)
#define SRAMFLASH			(FACTORYREGION_BASE + 0x018)

#define CPUSS_BASE			0x40400000U
#define CPUSS_CTL			(CPUSS_BASE + 0x1300)

#define SYSCTL_BASE			0x400AF000U
#define SYSCTL_RESETLEVEL	(SYSCTL_BASE + 0x1300)
#define SYSCTL_RESETCMD		(SYSCTL_BASE + 0x1304)

/* Debug subsystem mailbox */
#define DEBUGSS_BASE		0x400C7000
#define DSSM_TXD		    (DEBUGSS_BASE + 0x1100)
// bit 1 "has data" rest "SW defined"
#define DSSM_TXCTL		    (DEBUGSS_BASE + 0x1104)
#define DSSM_RXD		    (DEBUGSS_BASE + 0x1108)
// bit 1 "has data" 1-7 "flags"
#define DSSM_RXCTL		    (DEBUGSS_BASE + 0x110C)

// aliases for easier copy-pasting from the .gel files
#define SECAP_TDR DSSM_TXD
#define SECAP_TCR DSSM_TXCTL
#define SECAP_RDR DSSM_RXD
#define SECAP_RCR DSSM_RXCTL

// "uniflash_8.4.0/deskdb/content/TICloudAgent/win/ccs_base/emulation/gel/mspm0_cs_dap_init.gel"
// begin copy-pasted defs from .gel file
/* Definitions of DSSM commands */
#define DSSM_BC_FACTORY_RESET                 (0x020AU)
#define DSSM_BC_MASS_ERASE                    (0x020CU)
#define DSSM_BC_PW_AUTH                       (0x030EU)
#define DSSM_DATA_EXCHANGE                    (0x00EEU)

/* Definition of Masks */

#define DEBUGSS_SECAP_TCR_TRANSMIT_FULL_MASK  ((int)0x00000001U)
#define DEBUGSS_SECAP_TCR_TRANSMIT_EMPTY_MASK ((int)0x00000000U)
#define DEBUGSS_SECAP_RCR_RECEIVE_FULL_MASK   ((int)0x00000001U)
#define DEBUGSS_SECAP_RCR_RECEIVE_EMPTY_MASK  ((int)0x00000000U)
#define SECAP_CTL_MASK                        (0xFFFFU)
#define SECAP_CMD_MASK                        (0x00FEU)

#define DSSM_CMD_RECEIVED                     (0x0100U)
#define DSSM_CMD_NOT_RECEIVED                 (0x0101U)
#define DSSM_ERROR_UNEXPECTED_COMMAND         (0x0102U)

#define RESET_LEN_POR                         (1500)
#define RESET_LEN_BOOTRST                     (1)

#define PASSWORD_LENGTH                       (4)
//#define PASSWORD_DATA_1                       (0x04030201)
//#define PASSWORD_DATA_2                       (0x08070605)
//#define PASSWORD_DATA_3                       (0x12111009)
//#define PASSWORD_DATA_4                       (0x16151413)

// end copy-pasted defs from .gel file

#define NONMAIN_BASE		0x41C00000
// TODO: mass erase / factory reset policies live here
#define BOOTCFG3			(NONMAIN_BASE + 0x20)
#define FLASHSWP0			(NONMAIN_BASE + 0x44)
#define FLASHSWP1			(NONMAIN_BASE + 0x48)

/* Not used for now - the whole "if your NOMNAIN CRC is wrong we brick the chip"
   is a little too terrifying, and we just factory reset when the flash is locked */
#define FLASHCTL_BASE       0x400CD000
#define FLASHCTL_IMASK		(FLASHCTL_BASE + 0x1028)
#define FLASHCTL_ICLR		(FLASHCTL_BASE + 0x1048)
#define CMDEXEC				(FLASHCTL_BASE + 0x1100)
#define CMDTYPE				(FLASHCTL_BASE + 0x1104)
#define CMDADDR				(FLASHCTL_BASE + 0x1120)
#define CMDBYTEEN			(FLASHCTL_BASE + 0x1124)
#define CMDDATA0			(FLASHCTL_BASE + 0x1130)
#define STATCMD				(FLASHCTL_BASE + 0x13D0)

enum CMDTYPE_COMMAND {
	CMDTYPE_NOOP 			= 0,
	CMDTYPE_PROGRAM 		= 1,
	CMDTYPE_ERASE 			= 2,
	CMDTYPE_READ_VERIFY 	= 3,
	CMDTYPE_BLANK_VERIFY 	= 6,
};
enum CMDTYPE_SIZE {
	CMDTYPE_1_WORD			= 0 << 4,
	CMDTYPE_2_WORD			= 1 << 4,
	CMDTYPE_4_WORD			= 2 << 4,
	CMDTYPE_8_WORD			= 3 << 4,
	CMDTYPE_SECTOR			= 4 << 4,
	CMDTYPE_BANK			= 5 << 4,
};

#define STATCMD_CMDDONE		(1 << 0)
#define STATCMD_CMDPASS		(1 << 1)
#define STATCMD_FAILWREPROT	(1 << 4)
#define STATCMD_FAILVERIFY	(1 << 5)
#define STATCMD_FAILILADDR	(1 << 6)
#define STATCMD_FAILMODE	(1 << 7)
#define STATCMD_FAILMISC	(1 << 12)

/* Dynamic write protection */
/* Bitfield: Sectors 0-31 of MAIN in BANK0 */
#define CMDWEPROTA			(FLASHCTL_BASE + 0x11D0)
/* BANK0:   sectors 32-255 in 8-sector increments, starting from bit 4
   BANK1-4: sectors  0-255 in 8-sector increments, all bits used */
#define CMDWEPROTB			(FLASHCTL_BASE + 0x11D4)
#define CMDWEPROTNM			(FLASHCTL_BASE + 0x1210)

#define FLASH_WORD_SIZE 8 // bytes

// Software triggers a BOOTRST through SYSCTL (RESETLEVEL 0x01)
// • The NRST pin is held low for longer than the minimum reset pulse time

// boot reset does config then does mass erase / factory reset

static int mspm0_mass_erase(struct flash_bank *bank);

struct mspm0_flash_bank {
	/* chip id registers */
	uint32_t traceid;
	uint32_t deviceid;
	uint32_t userid;
	uint32_t sramflash;

	/* parsed values from chip id registers */
	uint8_t version;
	uint16_t part;
	uint8_t variant;
	uint8_t major;
	uint8_t minor;
	uint16_t mainflash_sz; // KB
	uint8_t mainnumbanks; // 1 for all devices so far, need >128KB of flash for multi-bank
	uint32_t sram_sz; // KB
	uint32_t dataflash_sz; // KB

	const char *target_name;

	/* flash geometry */
	uint32_t num_pages;
	uint32_t pagesize;
};

static const struct {
	uint16_t part;
	uint8_t variant;
	const char *partname;
} mspm0_parts[] = {
	{0xAE2D, 0xC7, "MSPM0G3507SPMR"},
	{0xAE2D, 0xF7, "MSPM0G3507SRGZR"},
	{0xAE2D, 0x3F, "MSPM0G3507SPTR"},
	{0xAE2D, 0x4C, "MSPM0G3507SRHBR"},
	{0xAE2D, 0xCA, "MSPM0G3507SDGS28R"},
	{0x151F, 0xD4, "MSPM0G3506SPMR"},
	{0x151F, 0xFE, "MSPM0G3506SRGZR"},
	{0x151F, 0x39, "MSPM0G3506SPTR"},
	{0x151F, 0xB5, "MSPM0G3506SRHBR"},
	{0x151F, 0x08, "MSPM0G3506SDGS28R"},
	{0xC504, 0x1D, "MSPM0G3505SPMR"},
	{0xC504, 0xC7, "MSPM0G3505SRGZR"},
	{0xC504, 0x93, "MSPM0G3505SPTR"},
	{0xC504, 0xE7, "MSPM0G3505SRHBR"},
	{0xC504, 0x8E, "MSPM0G3505SDGS28R"},
	{0xC504, 0xDF, "MSPM0G3505TDGS28R"},
	{0x0000, 0x00, "Unknown Part"}
};

/***************************************************************************
*	openocd command interface                                              *
***************************************************************************/

/* flash_bank mspm0 <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(mspm0_flash_bank_command)
{
	struct mspm0_flash_bank *mspm0_info;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	mspm0_info = calloc(sizeof(struct mspm0_flash_bank), 1);
	bank->base = 0x0;
	bank->driver_priv = mspm0_info;

	mspm0_info->target_name = "Unknown target";

	/* part wasn't probed for info yet */
	mspm0_info->userid = 0;

	return ERROR_OK;
}

/***************************************************************************
*	chip identification and status                                         *
***************************************************************************/

/* Read device id register and fill in driver info structure */
static int mspm0_read_part_info(struct flash_bank *bank)
{
	struct mspm0_flash_bank *mspm0_info = bank->driver_priv;
	struct target *target = bank->target;
	uint16_t manufacturer, partnum;
	int i;

	/* Read and parse chip identification register */
	target_read_u32(target, TRACEID, &mspm0_info->traceid);
	target_read_u32(target, DEVICEID, &mspm0_info->deviceid);
	target_read_u32(target, USERID, &mspm0_info->userid);
	target_read_u32(target, SRAMFLASH, &mspm0_info->sramflash);
	LOG_DEBUG("traceid 0x%" PRIx32 ", deviceid 0x%" PRIx32 ", userid 0x%" PRIx32 ", sramflash 0x%" PRIx32 "",
		  mspm0_info->traceid, mspm0_info->deviceid, mspm0_info->userid, mspm0_info->sramflash);

	mspm0_info->part = mspm0_info->userid & 0xFFFF;
	mspm0_info->variant = (mspm0_info->userid >> 16) & 0xFF;
	mspm0_info->minor = (mspm0_info->userid >> 24) & 0x0F;
	mspm0_info->major = (mspm0_info->userid >> 28) & 0x07;

	mspm0_info->mainflash_sz = mspm0_info->sramflash & 0x0FFF;
	mspm0_info->mainnumbanks = ((mspm0_info->sramflash >> 12) & 0x3) + 1;
	mspm0_info->sram_sz = (mspm0_info->sramflash >> 16) & 0x3FF;
	mspm0_info->dataflash_sz = mspm0_info->sramflash >> 26;

	manufacturer = (mspm0_info->deviceid >> 1) & 0x7ff;
	partnum = (mspm0_info->deviceid >> 12) & 0xFFFF;

	if ((manufacturer != 0x17) || (partnum != 0xBB88)) {
		LOG_WARNING(
			"Cannot identify target as MSPM0, mfr/partnum = 0x%" PRIX16 "/0x%" PRIX16,
			manufacturer, partnum);
		return ERROR_FLASH_OPERATION_FAILED;
	}

	mspm0_info->version = mspm0_info->deviceid >> 28;

	if (mspm0_info->dataflash_sz != 0) {
		// maybe this should be a soft error?
		LOG_WARNING("Nonzero dataflash size is currently unsupported");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	for (i = 0; mspm0_parts[i].part; i++) {
		if ((mspm0_parts[i].part == mspm0_info->part) &&
				(mspm0_parts[i].variant == mspm0_info->variant))
			break;
	}

	mspm0_info->target_name = mspm0_parts[i].partname;

	mspm0_info->num_pages = mspm0_info->mainflash_sz;
	mspm0_info->pagesize = 1024;

	LOG_INFO(
			"TI MSPM0 detected: Chip is "
			"%s (part/variant %04" PRIX16 "/%02" PRIX8 ") die rev %" PRId8 " SKU rev %" PRId8 ".%" PRId8,
			mspm0_info->target_name,
			mspm0_info->part,
			mspm0_info->variant,
			mspm0_info->version,
			mspm0_info->major,
			mspm0_info->minor);

	LOG_INFO(
			"eproc: %s, flash: %" PRIu16 "k, banks: %" PRIu8 ", sram: %" PRIu32 "k dataflash: %" PRIu32 "k",
			"ARMv6M",
			mspm0_info->mainflash_sz,
			mspm0_info->mainnumbanks,
			mspm0_info->sram_sz,
			mspm0_info->dataflash_sz
			);

	LOG_INFO(
			"pagesize: %" PRIu32 ", pages: %" PRIu32,
			mspm0_info->pagesize,
			mspm0_info->num_pages);

	return ERROR_OK;
}

/***************************************************************************
*	flash operations                                                       *
***************************************************************************/

static int mspm0_protect_check(struct flash_bank *bank)
{
	struct mspm0_flash_bank *mspm0_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t flashswp0, flashswp1;

	if (mspm0_info->userid == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;

	for (unsigned int i = 0; i < bank->num_sectors; i++)
		bank->sectors[i].is_protected = -1;

	target_read_u32(target, FLASHSWP0, &flashswp0);
	target_read_u32(target, FLASHSWP1, &flashswp1);

	// first 32 sectors: 1k granularity
	for (unsigned int i = 0; i < 32 && i < bank->num_sectors; i++) {
		bank->sectors[i].is_protected = !(flashswp0 & (1 << i));
	}

	// remaining sectors: 8k granularity. Skip first 32 sectors, covered by swp0
	for (unsigned int i = 32; i < bank->num_sectors; i++) {
		bank->sectors[i].is_protected = !(flashswp1 & (1 << (i/8)));
	}

	return ERROR_OK;
}

static bool flash_op_ok(struct target *target, const char *op, uint32_t address) {
	uint32_t stat_cmd;
	// unsigned i = 0;
	do {
		target_read_u32(target, STATCMD, &stat_cmd);
		// i++;
	} while (!(stat_cmd & STATCMD_CMDDONE));

	// LOG_INFO("Flash op %s at %X finished after %d loops", op, address, i);

	/* Check access violations */
	if (!(stat_cmd & STATCMD_CMDPASS)) {
		if (stat_cmd & STATCMD_FAILWREPROT) {
			LOG_WARNING("Failed to %s 0x%" PRIX32 ", page is write protected (STATCMD.FAILWREPROT asserted)",
								op, address);
		} else if (stat_cmd & STATCMD_FAILVERIFY) {
			LOG_WARNING("Failed to %s 0x%" PRIX32 ", on-chip timeout (STATCMD.FAILVERIFY asserted)",
								op, address);
		} else {
			LOG_WARNING("Failed to %s 0x%" PRIX32 ", STATCMD 0x%" PRIx32 "",
								op, address, stat_cmd);
		}

		return false;
	}

	return true;
}

static int mspm0_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	struct mspm0_flash_bank *mspm0_info = bank->driver_priv;
	struct target *target = bank->target;

	// LOG_INFO("Erasing sectors %d to %d", first, last);

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (mspm0_info->userid == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;

	if ((last < first) || (last >= mspm0_info->num_pages))
		return ERROR_FLASH_SECTOR_INVALID;

	if ((first == 0) && (last == (mspm0_info->num_pages - 1)))
		return mspm0_mass_erase(bank);

	/* Clear and disable flash programming interrupts */
	target_write_u32(target, FLASHCTL_IMASK, 0);
	target_write_u32(target, FLASHCTL_ICLR, 0xFFFFFFFF);

	/* REVISIT this clobbers state set by any halted firmware ...
	 * it might want to process those IRQs.
	 */

	for (unsigned int page = first; page <= last; page++) {
		/* Unlock dynamic write protection - every erase op will set ALL pages
		 * to protected, so it's easier to just unlock everything since they'll
		 * be reset right after.
		 */
		if (page < 32) {
			target_write_u32(target, CMDWEPROTA, 0);
		} else {
			target_write_u32(target, CMDWEPROTB, 0);
		}

		/* Address is first word in page */
		target_write_u32(target, CMDADDR, page * mspm0_info->pagesize);
		/* Write erase command */
		target_write_u32(target, CMDTYPE, CMDTYPE_ERASE | CMDTYPE_SECTOR);
		/* Execute */
		target_write_u32(target, CMDEXEC, 1);
		/* Wait until erase complete */
		if (!flash_op_ok(target, "erase", page * mspm0_info->pagesize)) {
			return ERROR_FLASH_OPERATION_FAILED;
		}
	}

	return ERROR_OK;
}

/* see contrib/loaders/flash/stellaris.s for src */

static const uint8_t stellaris_write_code[] = {
								/* write: */
	0xDF, 0xF8, 0x40, 0x40,		/* ldr		r4, pFLASH_CTRL_BASE */
	0xDF, 0xF8, 0x40, 0x50,		/* ldr		r5, FLASHWRITECMD */
								/* wait_fifo: */
	0xD0, 0xF8, 0x00, 0x80,		/* ldr		r8, [r0, #0] */
	0xB8, 0xF1, 0x00, 0x0F,		/* cmp		r8, #0 */
	0x17, 0xD0,					/* beq		exit */
	0x47, 0x68,					/* ldr		r7, [r0, #4] */
	0x47, 0x45,					/* cmp		r7, r8 */
	0xF7, 0xD0,					/* beq		wait_fifo */
								/* mainloop: */
	0x22, 0x60,					/* str		r2, [r4, #0] */
	0x02, 0xF1, 0x04, 0x02,		/* add		r2, r2, #4 */
	0x57, 0xF8, 0x04, 0x8B,		/* ldr		r8, [r7], #4 */
	0xC4, 0xF8, 0x04, 0x80,		/* str		r8, [r4, #4] */
	0xA5, 0x60,					/* str		r5, [r4, #8] */
								/* busy: */
	0xD4, 0xF8, 0x08, 0x80,		/* ldr		r8, [r4, #8] */
	0x18, 0xF0, 0x01, 0x0F,		/* tst		r8, #1 */
	0xFA, 0xD1,					/* bne		busy */
	0x8F, 0x42,					/* cmp		r7, r1 */
	0x28, 0xBF,					/* it		cs */
	0x00, 0xF1, 0x08, 0x07,		/* addcs	r7, r0, #8 */
	0x47, 0x60,					/* str		r7, [r0, #4] */
	0x01, 0x3B,					/* subs		r3, r3, #1 */
	0x03, 0xB1,					/* cbz		r3, exit */
	0xE2, 0xE7,					/* b		wait_fifo */
								/* exit: */
	0x00, 0xBE,					/* bkpt		#0 */

	/* pFLASH_CTRL_BASE: */
	0x00, 0xD0, 0x0F, 0x40,	/* .word	0x400FD000 */
	/* FLASHWRITECMD: */
	0x01, 0x00, 0x42, 0xA4	/* .word	0xA4420001 */
};
static int mspm0_write_block(struct flash_bank *bank,
		const uint8_t *buffer, uint32_t offset, uint32_t wcount)
{
	struct target *target = bank->target;
	uint32_t buffer_size = 16384;
	struct working_area *source;
	struct working_area *write_algorithm;
	uint32_t address = bank->base + offset;
	struct reg_param reg_params[4];
	struct arm_algorithm armv4_5_algo;
	int retval = ERROR_OK;

	/* TODO */
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	/* power of two, and multiple of word size */
	static const unsigned buf_min = 128;

	/* for small buffers it's faster not to download an algorithm */
	if (wcount * 4 < buf_min)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	LOG_DEBUG("(bank=%p buffer=%p offset=%08" PRIx32 " wcount=%08" PRIx32 "",
			bank, buffer, offset, wcount);

	/* flash write code */
	if (target_alloc_working_area(target, sizeof(stellaris_write_code),
			&write_algorithm) != ERROR_OK) {
		LOG_DEBUG("no working area for block memory writes");
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	/* plus a buffer big enough for this data */
	if (wcount * 4 < buffer_size)
		buffer_size = wcount * 4;

	/* memory buffer */
	while (target_alloc_working_area_try(target, buffer_size, &source) != ERROR_OK) {
		buffer_size /= 2;
		if (buffer_size <= buf_min) {
			target_free_working_area(target, write_algorithm);
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
		LOG_DEBUG("retry target_alloc_working_area(%s, size=%u)",
				target_name(target), (unsigned) buffer_size);
	}

	target_write_buffer(target, write_algorithm->address,
			sizeof(stellaris_write_code),
			stellaris_write_code);

	armv4_5_algo.common_magic = ARM_COMMON_MAGIC;
	armv4_5_algo.core_mode = ARM_MODE_THREAD;
	armv4_5_algo.core_state = ARM_STATE_THUMB;

	init_reg_param(&reg_params[0], "r0", 32, PARAM_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);
	init_reg_param(&reg_params[3], "r3", 32, PARAM_OUT);

	buf_set_u32(reg_params[0].value, 0, 32, source->address);
	buf_set_u32(reg_params[1].value, 0, 32, source->address + source->size);
	buf_set_u32(reg_params[2].value, 0, 32, address);
	buf_set_u32(reg_params[3].value, 0, 32, wcount);

	retval = target_run_flash_async_algorithm(target, buffer, wcount, 4,
			0, NULL,
			4, reg_params,
			source->address, source->size,
			write_algorithm->address, 0,
			&armv4_5_algo);

	if (retval == ERROR_FLASH_OPERATION_FAILED)
		LOG_ERROR("error %d executing stellaris flash write algorithm", retval);

	target_free_working_area(target, write_algorithm);
	target_free_working_area(target, source);

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);

	return retval;
}

static int mspm0_write_word(struct target *target, struct mspm0_flash_bank *mspm0_info,
		uint32_t address, const uint8_t buffer[FLASH_WORD_SIZE], uint32_t mask) {
	uint32_t page;

	if (!(address & 0xff))
		LOG_DEBUG("0x%" PRIx32 "", address);

	page = address / mspm0_info->pagesize;
	/* Unlock dynamic write protection - every program op will set ALL pages
		* to protected, so it's easier to just unlock everything since they'll
		* be reset right after.
		*/
	if (page < 32) {
		target_write_u32(target, CMDWEPROTA, 0);
	} else {
		target_write_u32(target, CMDWEPROTB, 0);
	}

	/* Program one word - don't bother working out if the device supports multi-word ops */
	target_write_u32(target, CMDADDR, address);
	target_write_u32(target, CMDTYPE, CMDTYPE_PROGRAM | CMDTYPE_1_WORD);
	/* REVISIT: apparently some devices have 128-bit word sizes */
	/* 0x100: always enable ECC */
	target_write_u32(target, CMDBYTEEN, 0x100 | mask);
	/* Don't need to modify CMDCTL because automatic ECC is on by default */
	/* target_write_u32(target, CMDCTL, ...); */
	target_write_buffer(target, CMDDATA0, FLASH_WORD_SIZE, buffer);
	target_write_u32(target, CMDEXEC, 1);
	/* Wait until write complete */
	if (!flash_op_ok(target, "write", address)) {
		return ERROR_FLASH_OPERATION_FAILED;
	}

	return ERROR_OK;
}

static int mspm0_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct mspm0_flash_bank *mspm0_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t address = offset;
	uint32_t stat_cmd;
	uint32_t words_remaining = (count / FLASH_WORD_SIZE);
	uint32_t bytes_remaining = (count & (FLASH_WORD_SIZE - 1));
	uint32_t bytes_written = 0;
	int retval;

	// LOG_INFO("Writing %d bytes to %X", count, offset);

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	LOG_DEBUG("(bank=%p buffer=%p offset=%08" PRIx32 " count=%08" PRIx32 "",
			bank, buffer, offset, count);

	if (mspm0_info->userid == 0)
		return ERROR_FLASH_BANK_NOT_PROBED;

	if (offset & (FLASH_WORD_SIZE - 1)) {
		LOG_WARNING("offset size must be word aligned");
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	if (offset + count > bank->size)
		return ERROR_FLASH_DST_OUT_OF_BANK;

	/* Clear and disable flash programming interrupts */
	target_write_u32(target, FLASHCTL_IMASK, 0);
	target_write_u32(target, FLASHCTL_ICLR, 0xFFFFFFFF);

	/* REVISIT this clobbers state set by any halted firmware ...
	 * it might want to process those IRQs.
	 */

	/* multiple words to be programmed? */
	if (words_remaining > 0) {
		/* try using a block write */
		retval = mspm0_write_block(bank, buffer, offset,
				words_remaining);
		if (retval != ERROR_OK) {
			if (retval == ERROR_TARGET_RESOURCE_NOT_AVAILABLE) {
				LOG_DEBUG("writing flash word-at-a-time");
			} else if (retval == ERROR_FLASH_OPERATION_FAILED) {
				/* if an error occurred, we examine the reason, and quit */
				target_read_u32(target, STATCMD, &stat_cmd);

				LOG_ERROR("flash writing failed with STATCMD: 0x%" PRIx32 "", stat_cmd);
				return ERROR_FLASH_OPERATION_FAILED;
			}
		} else {
			buffer += words_remaining * FLASH_WORD_SIZE;
			address += words_remaining * FLASH_WORD_SIZE;
			words_remaining = 0;
		}
	}

	while (words_remaining > 0) {
		if (mspm0_write_word(target, mspm0_info, address, buffer, 0xFF) != ERROR_OK) {
			return ERROR_FLASH_OPERATION_FAILED;
		}

		buffer += FLASH_WORD_SIZE;
		address += FLASH_WORD_SIZE;
		words_remaining--;
	}

	if (bytes_remaining) {
		uint8_t last_word[FLASH_WORD_SIZE] = {0};

		/* copy the last remaining bytes into the write buffer */
		memcpy(last_word, buffer+bytes_written, bytes_remaining);

		if (mspm0_write_word(target, mspm0_info, address, last_word, 0xFF >> bytes_remaining) != ERROR_OK) {
			return ERROR_FLASH_OPERATION_FAILED;
		}
	}

	/* There may be stale data in the processor's cache and prefetch logic.
	 * Flush the cache in the CPU subsystem so reads (eg verify) are up to date.
	 */
	target_write_u32(target, CPUSS_CTL, 0);


	return ERROR_OK;
}

static int mspm0_probe(struct flash_bank *bank)
{
	struct mspm0_flash_bank *mspm0_info = bank->driver_priv;
	int retval;

	/* If this is an MSPM0, it has flash; probe() is just
	 * to figure out how much is present.  Only do it once.
	 */
	if (mspm0_info->userid != 0)
		return ERROR_OK;

	/* mspm0_read_part_info() already handled error checking and
	 * reporting.  Note that it doesn't write, so we don't care about
	 * whether the target is halted or not.
	 */
	retval = mspm0_read_part_info(bank);
	if (retval != ERROR_OK)
		return retval;

	free(bank->sectors);

	/* provide this for the benefit of the NOR flash framework */
	bank->size = mspm0_info->num_pages * mspm0_info->pagesize;
	bank->num_sectors = mspm0_info->num_pages;
	bank->sectors = calloc(bank->num_sectors, sizeof(struct flash_sector));
	for (unsigned int i = 0; i < bank->num_sectors; i++) {
		bank->sectors[i].offset = i * mspm0_info->pagesize;
		bank->sectors[i].size = mspm0_info->pagesize;
		bank->sectors[i].is_erased = -1;
		bank->sectors[i].is_protected = -1;
	}

	return retval;
}

/*
 * Send a SEC_AP command
 */
static int SECAP_send_command(struct target *target, uint32_t cmd)
{
	int ret;

	ret = target_write_u32(target, SECAP_TCR, cmd);
	if(ret == ERROR_OK)
		ret = target_write_u32(target, SECAP_TDR, 0);

	return ret;
}

/*
 * Waits for a response after a command was executed
 */
static int SECAP_wait_response(struct target *target, uint32_t *rx_cmd, uint32_t *rx_resp)
{
    uint32_t cmd;
	int ret;

    do
    {
		ret = target_read_u32(target, SECAP_RCR, &cmd);
		cmd &= SECAP_CTL_MASK;
    } while(ret == ERROR_OK && (cmd & DEBUGSS_SECAP_RCR_RECEIVE_FULL_MASK) != DEBUGSS_SECAP_RCR_RECEIVE_FULL_MASK);

    *rx_cmd = (cmd & SECAP_CMD_MASK);
	if(ret == ERROR_OK)
		ret = target_read_u32(target, SECAP_RDR, rx_resp);

    return ret;
}

/*
 * Waits for a response after a command was executed
 */
static int remote_SECAP_command(struct target *target, uint32_t cmd)
{
    int ret;
	uint32_t rx_cmd, rx_resp;

    if((ret = SECAP_send_command(target, cmd)) != ERROR_OK) {
		return ERROR_FAIL;
	}
    LOG_INFO("Command Sent");

    usleep(1000);

    SECAP_wait_response(target, &rx_cmd, &rx_resp);
    if ( rx_cmd != (cmd & SECAP_CMD_MASK) ||
         (rx_resp >> 8) != DSSM_CMD_RECEIVED) {
        LOG_ERROR("Send cmd %x but got cmd = %x resp = %x", cmd, rx_cmd, rx_resp);
		return ERROR_FAIL;
    }
	// else {
		// TODO: handle data sending if we ever need it
        // if ('GEL'::gDAPSecAPDataLen > 0) {
        //     GEL_TextOut("Send Data...\n");
        //     GEL_DAPInit_transmitData('GEL'::gDAPSecAPDataLen);
        //     SECAP_wait_response();
        //     if ( ('GEL'::gDAPRxCmd != ('GEL'::gDAPSecAPCmd & SECAP_CMD_MASK)) ||
        //          (('GEL'::gDAPRxResp >> 8) != 0x200) ) {
        //         GEL_TextOut("Command = %x \n",,,,, 'GEL'::gDAPRxCmd);
        //         GEL_TextOut("Response = %x \n",,,,, 'GEL'::gDAPRxResp);
        //     } else {
        //         success = 1;
        //     }
        // } else {
        //     success = 1;
        // }
    // }

	return ERROR_OK;
}

static int mspm0_mass_erase(struct flash_bank *bank)
{
	LOG_INFO("Initiating mspm0 Mass Erase");

	// perform operation in reset to ensure it works in the presence of
	// broken firmware.
	// TODO: make this a command arg
	// TODO: optional user-held reset
	if (!(jtag_get_reset_config() & RESET_HAS_SRST)) {
		LOG_ERROR("Can't mass erase MSPM0 without an SRST pin");
		return ERROR_FAIL;
	}
	adapter_assert_reset();

	if (remote_SECAP_command(bank->target, DSSM_BC_MASS_ERASE) == ERROR_OK)
		LOG_INFO("mspm0 Mass Erase complete");
	else
		LOG_ERROR("mspm0 Mass Erase failed");

	adapter_deassert_reset();

	return ERROR_OK;
}

COMMAND_HANDLER(mspm0_handle_mass_erase_command)
{
	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	return mspm0_mass_erase(bank);
}

COMMAND_HANDLER(mspm0_handle_factory_reset_command)
{
	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK) {
		LOG_ERROR("Cannot get flash bank");
		return retval;
	}

	LOG_INFO("Initiating mspm0 Factory Reset");

	// perform operation in reset to ensure it works in the presence of
	// broken firmware.
	// TODO: make this a command arg
	// TODO: optional user-held reset
	if (!(jtag_get_reset_config() & RESET_HAS_SRST)) {
		LOG_ERROR("Can't factory reset MSPM0 without an SRST pin");
		return ERROR_FAIL;
	}
	adapter_assert_reset();

	if (remote_SECAP_command(bank->target, DSSM_BC_FACTORY_RESET) == ERROR_OK)
		LOG_INFO("mspm0 Factory Reset complete");
	else
		LOG_INFO("mspm0 Factory Reset failed");

	adapter_deassert_reset();

	return ERROR_OK;
}

// TODO: jank, copy-pasted statics
static int cortex_m_write_debug_halt_mask(struct target *target,
	uint32_t mask_on, uint32_t mask_off)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;

	/* mask off status bits */
	cortex_m->dcb_dhcsr &= ~((0xFFFFul << 16) | mask_off);
	/* create new register mask */
	cortex_m->dcb_dhcsr |= DBGKEY | C_DEBUGEN | mask_on;

	LOG_TARGET_DEBUG(target, "mem_ap_write_atomic_u32(): address: DCB_DHCSR value 0x%04X", cortex_m->dcb_dhcsr);
	return mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DHCSR, cortex_m->dcb_dhcsr);
}
static int cortex_m_clear_halt(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = &cortex_m->armv7m;
	int retval;

	/* clear step if any */
	cortex_m_write_debug_halt_mask(target, C_HALT, C_STEP);

	/* Read Debug Fault Status Register */
	retval = mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_DFSR, &cortex_m->nvic_dfsr);
	if (retval != ERROR_OK)
		return retval;

	/* Clear Debug Fault Status */
	retval = mem_ap_write_atomic_u32(armv7m->debug_ap, NVIC_DFSR, cortex_m->nvic_dfsr);
	if (retval != ERROR_OK)
		return retval;
	LOG_TARGET_DEBUG(target, "NVIC_DFSR 0x%" PRIx32 "", cortex_m->nvic_dfsr);

	return ERROR_OK;
}
static int cortex_m_set_maskints(struct target *target, bool mask)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	if (!!(cortex_m->dcb_dhcsr & C_MASKINTS) != mask)
		return cortex_m_write_debug_halt_mask(target, mask ? C_MASKINTS : 0, mask ? 0 : C_MASKINTS);
	else
		return ERROR_OK;
}
static int cortex_m_set_maskints_for_run(struct target *target)
{
	switch (target_to_cm(target)->isrmasking_mode) {
		case CORTEX_M_ISRMASK_AUTO:
			/* interrupts taken at resume, whether for step or run -> no mask */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_OFF:
			/* interrupts never masked */
			return cortex_m_set_maskints(target, false);

		case CORTEX_M_ISRMASK_ON:
			/* interrupts always masked */
			return cortex_m_set_maskints(target, true);

		case CORTEX_M_ISRMASK_STEPONLY:
			/* interrupts masked for single step only -> no mask */
			return cortex_m_set_maskints(target, false);
	}
	return ERROR_OK;
}
static inline void cortex_m_cumulate_dhcsr_sticky(struct cortex_m_common *cortex_m,
		uint32_t dhcsr)
{
	cortex_m->dcb_dhcsr_cumulated_sticky |= dhcsr;
}
static int cortex_m_read_dhcsr_atomic_sticky(struct target *target)
{
	struct cortex_m_common *cortex_m = target_to_cm(target);
	struct armv7m_common *armv7m = target_to_armv7m(target);

	int retval = mem_ap_read_atomic_u32(armv7m->debug_ap, DCB_DHCSR,
				&cortex_m->dcb_dhcsr);
	if (retval != ERROR_OK)
		return retval;

	LOG_TARGET_DEBUG(target, "cortex_m_read_dhcsr_atomic_sticky(): address: DCB_DHCSR value 0x%04X", cortex_m->dcb_dhcsr);

	cortex_m_cumulate_dhcsr_sticky(cortex_m, cortex_m->dcb_dhcsr);
	return ERROR_OK;
}

// mostly just copied from cortex_m_assert_reset
COMMAND_HANDLER(mspm0_handle_reset_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct cortex_m_common *cortex_m = target_to_cm(target);
	int retval;
	uint32_t reset_req;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (strcmp(*CMD_ARGV, "sysrst") == 0)
		reset_req = 0;

	else if (strcmp(*CMD_ARGV, "bsl") == 0) {
		reset_req = 2;

	} else
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct armv7m_common *armv7m = &cortex_m->armv7m;

	LOG_TARGET_DEBUG(target, "target->state: %s,%s examined",
		target_state_name(target),
		target_was_examined(target) ? "" : " not");

	/* We need at least debug_ap to go further.
	 * Inform user and bail out if we don't have one. */
	if (!armv7m->debug_ap) {
		LOG_TARGET_ERROR(target, "Debug AP not available, reset NOT asserted!");
		return ERROR_FAIL;
	}

	/* Enable debug requests */
	LOG_TARGET_DEBUG(target, "cortex_m_read_dhcsr_atomic_sticky J");
	retval = cortex_m_read_dhcsr_atomic_sticky(target);

	/* Store important errors instead of failing and proceed to reset assert */

	if (retval != ERROR_OK || !(cortex_m->dcb_dhcsr & C_DEBUGEN))
		retval = cortex_m_write_debug_halt_mask(target, 0, C_HALT | C_STEP | C_MASKINTS);

	/* If the processor is sleeping in a WFI or WFE instruction, the
	 * C_HALT bit must be asserted to regain control */
	if (retval == ERROR_OK && (cortex_m->dcb_dhcsr & S_SLEEP))
		retval = cortex_m_write_debug_halt_mask(target, C_HALT, 0);

	mem_ap_write_u32(armv7m->debug_ap, DCB_DCRDR, 0);
	/* Ignore less important errors */

	if (!target->reset_halt) {
		/* Set/Clear C_MASKINTS in a separate operation */
		cortex_m_set_maskints_for_run(target);

		/* clear any debug flags before resuming */
		cortex_m_clear_halt(target);

		/* clear C_HALT in dhcsr reg */
		cortex_m_write_debug_halt_mask(target, 0, C_HALT);
	} else {
		/* Halt in debug on reset; endreset_event() restores DEMCR.
		 *
		 * REVISIT catching BUSERR presumably helps to defend against
		 * bad vector table entries.  Should this include MMERR or
		 * other flags too?
		 */
		int retval2;
		retval2 = mem_ap_write_atomic_u32(armv7m->debug_ap, DCB_DEMCR,
				TRCENA | VC_HARDERR | VC_BUSERR | VC_CORERESET);
		if (retval != ERROR_OK || retval2 != ERROR_OK)
			LOG_TARGET_INFO(target, "AP write error, reset will not halt");
	}

	int retval3;
	// The key MSPM0 change - writing to SYSCTL instead
	retval3 = mem_ap_write_atomic_u32(armv7m->debug_ap, SYSCTL_RESETLEVEL, reset_req);
	// KEY and GO
	retval3 = mem_ap_write_atomic_u32(armv7m->debug_ap, SYSCTL_RESETCMD, 0xE4000001);
	jtag_sleep(5000);

	retval3 = dap_dp_init_or_reconnect(armv7m->debug_ap->dap);
	if (retval3 != ERROR_OK) {
		// note: always happens on M0 for whatever reason
		// LOG_TARGET_ERROR(target, "DP initialisation failed");
		/* The error return value must not be propagated in this case.
			* SYSRST or VECTRESET has been triggered so reset processing
			* should continue */
	} else {
		/* I do not know why this is necessary, but it
			* fixes strange effects (step/resume cause NMI
			* after reset) on LM3S6918 -- Michael Schwingen
			*/
		uint32_t tmp;
		mem_ap_read_atomic_u32(armv7m->debug_ap, NVIC_AIRCR, &tmp);
	}

	target->state = TARGET_RESET;
	jtag_sleep(50000);

	register_cache_invalidate(cortex_m->armv7m.arm.core_cache);

	/* now return stored error code if any */
	if (retval != ERROR_OK)
		return retval;

	if (target->reset_halt && target_was_examined(target)) {
		retval = target_halt(target);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static const struct command_registration mspm0_exec_command_handlers[] = {
	{
		.name = "mass_erase",
		.handler = mspm0_handle_mass_erase_command,
		.mode = COMMAND_EXEC,
		.help = "erase entire device",
		.usage = "",
	},
	{
		.name = "factory_reset",
		.handler = mspm0_handle_factory_reset_command,
		.mode = COMMAND_EXEC,
		.help = "factory reset (and erase) device, including setting NONMAIN to defaults",
		.usage = "",
	},
	{
		.name = "reset",
		.handler = mspm0_handle_reset_command,
		.mode = COMMAND_EXEC,
		.help = "soft reset the MCU, either a sysreset, or sysreset into the BSL",
		.usage = "['sysrst'|'bsl']",
	},
	COMMAND_REGISTRATION_DONE
};
static const struct command_registration mspm0_command_handlers[] = {
	{
		.name = "mspm0",
		.mode = COMMAND_EXEC,
		.help = "MSPM0 flash command group",
		.usage = "",
		.chain = mspm0_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver mspm0_flash = {
	.name = "mspm0",
	.commands = mspm0_command_handlers,
	.flash_bank_command = mspm0_flash_bank_command,
	.erase = mspm0_erase,
	.protect = NULL,
	.write = mspm0_write,
	.read = default_flash_read,
	.probe = mspm0_probe,
	.auto_probe = mspm0_probe,
	/* TODO: erased pages are not deterministic, i.e. not all 1s. Implement this! */
	.erase_check = default_flash_blank_check,
	.protect_check = mspm0_protect_check,
	.info = NULL,
	.free_driver_priv = default_flash_free_driver_priv,
};
