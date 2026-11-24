/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Riff: some Microsoft 6.18 stable kernels (6.18.33 - 6.18.35) carry the
 * first form of the typed allocators, where the gfp argument is required
 * (kzalloc_obj(P, GFP)). Backports 7.2 calls the later form, where it is
 * optional. Included after the kernel's <linux/slab.h> (build-pack.sh adds
 * it only for those kernels): replace them with the optional-gfp form.
 */
#ifndef __RIFF_SLAB_OBJ_H
#define __RIFF_SLAB_OBJ_H

#define __riff_obj_gfp_sel(g, ...) g
#define __riff_obj_gfp(...) __riff_obj_gfp_sel(__VA_ARGS__ __VA_OPT__(,) GFP_KERNEL)

#undef kmalloc_obj
#undef kzalloc_obj
#undef kmalloc_objs
#undef kzalloc_objs
#undef kmalloc_flex
#undef kzalloc_flex
#undef kvmalloc_obj
#undef kvzalloc_obj
#undef kvmalloc_objs
#undef kvzalloc_objs

#define kmalloc_obj(P, ...) \
	((typeof(P) *)kmalloc(sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kzalloc_obj(P, ...) \
	((typeof(P) *)kzalloc(sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kmalloc_objs(P, N, ...) \
	((typeof(P) *)kmalloc_array(N, sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kzalloc_objs(P, N, ...) \
	((typeof(P) *)kcalloc(N, sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kmalloc_flex(P, FAM, N, ...) \
	((typeof(P) *)kmalloc(struct_size_t(typeof(P), FAM, N), __riff_obj_gfp(__VA_ARGS__)))
#define kzalloc_flex(P, FAM, N, ...) \
	((typeof(P) *)kzalloc(struct_size_t(typeof(P), FAM, N), __riff_obj_gfp(__VA_ARGS__)))
#define kvmalloc_obj(P, ...) \
	((typeof(P) *)kvmalloc(sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kvzalloc_obj(P, ...) \
	((typeof(P) *)kvzalloc(sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kvmalloc_objs(P, N, ...) \
	((typeof(P) *)kvmalloc_array(N, sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))
#define kvzalloc_objs(P, N, ...) \
	((typeof(P) *)kvcalloc(N, sizeof(typeof(P)), __riff_obj_gfp(__VA_ARGS__)))

#endif
