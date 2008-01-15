/*-
 * Copyright (c) 2006 Bernd Walter.  All rights reserved.
 * Copyright (c) 2006 M. Warner Losh.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * "$FreeBSD: src/sys/dev/mmc/mmcvar.h,v 1.1.2.1 2006/11/20 07:16:28 imp Exp $"
 */

#ifndef DEV_MMC_MMCVAR_H
#define DEV_MMC_MMCVAR_H

enum mmc_device_ivars {
    MMC_IVAR_DSR_IMP,
    MMC_IVAR_MEDIA_SIZE,
    MMC_IVAR_MODE,
    MMC_IVAR_RCA,
    MMC_IVAR_SECTOR_SIZE,
    MMC_IVAR_TRAN_SPEED,
//    MMC_IVAR_,
};

/*
 * Simplified accessors for pci devices
 */
#define MMC_ACCESSOR(var, ivar, type)					\
	__BUS_ACCESSOR(mmc, var, MMC, ivar, type)

MMC_ACCESSOR(dsr_imp, DSR_IMP, int)
MMC_ACCESSOR(media_size, MEDIA_SIZE, int)
MMC_ACCESSOR(mode, MODE, int)
MMC_ACCESSOR(rca, RCA, int)
MMC_ACCESSOR(sector_size, SECTOR_SIZE, int)
MMC_ACCESSOR(tran_speed, TRAN_SPEED, int)

#endif /* DEV_MMC_MMCVAR_H */
