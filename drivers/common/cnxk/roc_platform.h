/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_PLATFORM_H_
#define _ROC_PLATFORM_H_

#include <rte_alarm.h>
#include <rte_bitmap.h>
#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_interrupts.h>
#include <rte_io.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "roc_bits.h"

#if defined(__ARM_FEATURE_SVE)
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse+sve\n"
#else
#define PLT_CPU_FEATURE_PREAMBLE ".cpu generic+crc+lse\n"
#endif

#define PLT_ASSERT		 RTE_ASSERT
#define PLT_MEMZONE_NAMESIZE	 RTE_MEMZONE_NAMESIZE
#define PLT_STD_C11		 RTE_STD_C11
#define PLT_PTR_ADD		 RTE_PTR_ADD
#define PLT_MAX_RXTX_INTR_VEC_ID RTE_MAX_RXTX_INTR_VEC_ID
#define PLT_INTR_VEC_RXTX_OFFSET RTE_INTR_VEC_RXTX_OFFSET
#define PLT_MIN			 RTE_MIN
#define PLT_MAX			 RTE_MAX
#define PLT_DIM			 RTE_DIM
#define PLT_SET_USED		 RTE_SET_USED
#define PLT_STATIC_ASSERT(s)	 _Static_assert(s, #s)
#define PLT_ALIGN		 RTE_ALIGN
#define PLT_ALIGN_MUL_CEIL	 RTE_ALIGN_MUL_CEIL
#define PLT_MODEL_MZ_NAME	 "roc_model_mz"
#define PLT_CACHE_LINE_SIZE      RTE_CACHE_LINE_SIZE
#define BITMASK_ULL		 GENMASK_ULL

/** Divide ceil */
#define PLT_DIV_CEIL(x, y)			\
	({					\
		__typeof(x) __x = x;		\
		__typeof(y) __y = y;		\
		(__x + __y - 1) / __y;		\
	})

#define __plt_cache_aligned __rte_cache_aligned
#define __plt_always_inline __rte_always_inline
#define __plt_packed	    __rte_packed
#define __roc_api	    __rte_internal
#define plt_iova_t	    rte_iova_t

#define plt_pci_device		    rte_pci_device
#define plt_pci_read_config	    rte_pci_read_config
#define plt_pci_find_ext_capability rte_pci_find_ext_capability

#define plt_log2_u32	 rte_log2_u32
#define plt_cpu_to_be_16 rte_cpu_to_be_16
#define plt_be_to_cpu_16 rte_be_to_cpu_16
#define plt_cpu_to_be_32 rte_cpu_to_be_32
#define plt_be_to_cpu_32 rte_be_to_cpu_32
#define plt_cpu_to_be_64 rte_cpu_to_be_64
#define plt_be_to_cpu_64 rte_be_to_cpu_64

#define plt_align32prevpow2 rte_align32prevpow2

#define plt_bitmap			rte_bitmap
#define plt_bitmap_init			rte_bitmap_init
#define plt_bitmap_reset		rte_bitmap_reset
#define plt_bitmap_free			rte_bitmap_free
#define plt_bitmap_clear		rte_bitmap_clear
#define plt_bitmap_set			rte_bitmap_set
#define plt_bitmap_get			rte_bitmap_get
#define plt_bitmap_scan_init		__rte_bitmap_scan_init
#define plt_bitmap_scan			rte_bitmap_scan
#define plt_bitmap_get_memory_footprint rte_bitmap_get_memory_footprint

#define plt_spinlock_t	    rte_spinlock_t
#define plt_spinlock_init   rte_spinlock_init
#define plt_spinlock_lock   rte_spinlock_lock
#define plt_spinlock_unlock rte_spinlock_unlock

#define plt_intr_callback_register   rte_intr_callback_register
#define plt_intr_callback_unregister rte_intr_callback_unregister
#define plt_intr_disable	     rte_intr_disable
#define plt_thread_is_intr	     rte_thread_is_intr
#define plt_intr_callback_fn	     rte_intr_callback_fn

#define plt_alarm_set	 rte_eal_alarm_set
#define plt_alarm_cancel rte_eal_alarm_cancel

#define plt_intr_handle rte_intr_handle

#define plt_zmalloc(sz, align) rte_zmalloc("cnxk", sz, align)
#define plt_free	       rte_free

#define plt_read64(addr) rte_read64_relaxed((volatile void *)(addr))
#define plt_write64(val, addr)                                                 \
	rte_write64_relaxed((val), (volatile void *)(addr))

#define plt_wmb() rte_wmb()
#define plt_rmb() rte_rmb()
#define plt_io_wmb() rte_io_wmb()
#define plt_io_rmb() rte_io_rmb()

#define plt_mmap       mmap
#define PLT_PROT_READ  PROT_READ
#define PLT_PROT_WRITE PROT_WRITE
#define PLT_MAP_SHARED MAP_SHARED

#define plt_memzone	   rte_memzone
#define plt_memzone_lookup rte_memzone_lookup
#define plt_memzone_reserve_cache_align(name, sz)                              \
	rte_memzone_reserve_aligned(name, sz, 0, 0, RTE_CACHE_LINE_SIZE)
#define plt_memzone_free rte_memzone_free

#define plt_tsc_hz   rte_get_tsc_hz
#define plt_delay_ms rte_delay_ms
#define plt_delay_us rte_delay_us

#define plt_lcore_id rte_lcore_id

#define plt_strlcpy rte_strlcpy

/* Log */
extern int cnxk_logtype_base;
extern int cnxk_logtype_mbox;
extern int cnxk_logtype_npa;
extern int cnxk_logtype_nix;
extern int cnxk_logtype_npc;
extern int cnxk_logtype_sso;
extern int cnxk_logtype_tim;
extern int cnxk_logtype_tm;

#define plt_err(fmt, args...)                                                  \
	RTE_LOG(ERR, PMD, "%s():%u " fmt "\n", __func__, __LINE__, ##args)
#define plt_info(fmt, args...) RTE_LOG(INFO, PMD, fmt "\n", ##args)
#define plt_warn(fmt, args...) RTE_LOG(WARNING, PMD, fmt "\n", ##args)
#define plt_print(fmt, args...) RTE_LOG(INFO, PMD, fmt "\n", ##args)

/**
 * Log debug message if given subsystem logging is enabled.
 */
#define plt_dbg(subsystem, fmt, args...)                                       \
	rte_log(RTE_LOG_DEBUG, cnxk_logtype_##subsystem,                       \
		"[%s] %s():%u " fmt "\n", #subsystem, __func__, __LINE__,      \
		##args)

#define plt_base_dbg(fmt, ...)	plt_dbg(base, fmt, ##__VA_ARGS__)
#define plt_mbox_dbg(fmt, ...)	plt_dbg(mbox, fmt, ##__VA_ARGS__)
#define plt_npa_dbg(fmt, ...)	plt_dbg(npa, fmt, ##__VA_ARGS__)
#define plt_nix_dbg(fmt, ...)	plt_dbg(nix, fmt, ##__VA_ARGS__)
#define plt_npc_dbg(fmt, ...)	plt_dbg(npc, fmt, ##__VA_ARGS__)
#define plt_sso_dbg(fmt, ...)	plt_dbg(sso, fmt, ##__VA_ARGS__)
#define plt_tim_dbg(fmt, ...)	plt_dbg(tim, fmt, ##__VA_ARGS__)
#define plt_tm_dbg(fmt, ...)	plt_dbg(tm, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
#define CNXK_PCI_ID(subsystem_dev, dev)				\
	{							\
		RTE_CLASS_ANY_ID,				\
		PCI_VENDOR_ID_CAVIUM,				\
		(dev),						\
		PCI_ANY_ID,					\
		(subsystem_dev),				\
	}
#else
#define CNXK_PCI_ID(subsystem_dev, dev)				\
	{							\
		.class_id = RTE_CLASS_ANY_ID,			\
		.vendor_id = PCI_VENDOR_ID_CAVIUM,		\
		.device_id = (dev),				\
		.subsystem_vendor_id = PCI_ANY_ID,		\
		.subsystem_device_id = (subsystem_dev),		\
	}
#endif

__rte_internal
int roc_plt_init(void);

/* Init callbacks */
typedef int (*roc_plt_init_cb_t)(void);
int __roc_api roc_plt_init_cb_register(roc_plt_init_cb_t cb);

#endif /* _ROC_PLATFORM_H_ */
