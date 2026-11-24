/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Riff: shims so the backports 6.18 wireless stack (+ rtw89 from 7.2) builds
 * against Microsoft's stock WSL kernel (6.6). Included from backport.h, i.e.
 * before most kernel headers: macros only (expanded at the use site).
 * Each shim is keyed on the kernel version that introduced the API, so the
 * same tree keeps building when WSL moves to a newer kernel.
 */
#ifndef __RIFF_BP_COMPAT_H
#define __RIFF_BP_COMPAT_H
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,7,0)
#define napi_is_scheduled(n) test_bit(NAPI_STATE_SCHED, &(n)->state)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
/* no BH workqueues yet: a high-priority process-context queue is a safe
 * (slightly slower) substitute */
#define WQ_BH WQ_HIGHPRI
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,11,0)
/* no SYSFS_GROUP_INVISIBLE yet: hide each attribute instead of the group */
#define DEFINE_SIMPLE_SYSFS_GROUP_VISIBLE(name)				\
	static inline umode_t sysfs_group_visible_##name(		\
		struct kobject *kobj, struct attribute *a, int n)	\
	{								\
		return name##_group_visible(kobj) ? a->mode : 0;	\
	}
#define SYSFS_GROUP_VISIBLE(fn) sysfs_group_visible_##fn
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
#define devm_kmemdup_array(dev, src, n, size, gfp) \
	devm_kmemdup(dev, src, size_mul(n, size), gfp)
#endif

/* netmem descriptors: before 6.17 the page_pool pointer is in struct page */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,17,0)
#define pp_page_to_nmdesc(p) (p)
/* workqueues were per-CPU by default before WQ_PERCPU existed */
#define WQ_PERCPU 0
#endif

/* 7.x typed allocators: the gfp argument is optional (GFP_KERNEL) */
#ifndef kzalloc_obj
#define __riff_gfp_sel(g, ...) g
#define __riff_gfp(...) __riff_gfp_sel(__VA_ARGS__ __VA_OPT__(,) GFP_KERNEL)
#define kmalloc_obj(P, ...) \
	((typeof(P) *)kmalloc(sizeof(typeof(P)), __riff_gfp(__VA_ARGS__)))
#define kzalloc_obj(P, ...) \
	((typeof(P) *)kzalloc(sizeof(typeof(P)), __riff_gfp(__VA_ARGS__)))
#define kmalloc_objs(P, N, ...) \
	((typeof(P) *)kmalloc_array(N, sizeof(typeof(P)), __riff_gfp(__VA_ARGS__)))
#define kzalloc_objs(P, N, ...) \
	((typeof(P) *)kcalloc(N, sizeof(typeof(P)), __riff_gfp(__VA_ARGS__)))
#define kzalloc_flex(P, FAM, N, ...) \
	((typeof(P) *)kzalloc(struct_size_t(typeof(P), FAM, N), __riff_gfp(__VA_ARGS__)))
#endif
/* the kvmalloc forms came separately: keyed on their own name */
#ifndef kvzalloc_objs
#define __riff_kv_gfp_sel(g, ...) g
#define __riff_kv_gfp(...) __riff_kv_gfp_sel(__VA_ARGS__ __VA_OPT__(,) GFP_KERNEL)
#define kvmalloc_obj(P, ...) \
	((typeof(P) *)kvmalloc(sizeof(typeof(P)), __riff_kv_gfp(__VA_ARGS__)))
#define kvzalloc_obj(P, ...) \
	((typeof(P) *)kvzalloc(sizeof(typeof(P)), __riff_kv_gfp(__VA_ARGS__)))
#define kvmalloc_objs(P, N, ...) \
	((typeof(P) *)kvmalloc_array(N, sizeof(typeof(P)), __riff_kv_gfp(__VA_ARGS__)))
#define kvzalloc_objs(P, N, ...) \
	((typeof(P) *)kvcalloc(N, sizeof(typeof(P)), __riff_kv_gfp(__VA_ARGS__)))
#endif

#endif
