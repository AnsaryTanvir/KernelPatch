/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <asm/current.h>
#include <linux/fs.h>      // For PAGE_SIZE
#include <linux/slab.h>    // For kzalloc and kfree

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

#define PAGE_SIZE 4096
const char *margs = 0;
enum hook_type hook_type = NONE;

void before_mincore_0(hook_fargs4_t *args, void *udata)
{
    unsigned long start = (unsigned long)syscall_argn(args, 0);
    size_t len = (size_t)syscall_argn(args, 1);
    unsigned char __user *vec = (unsigned char __user *)syscall_argn(args, 2);

    pr_info("mincore syscall hooked: returning fake response\n");

    /* Populate the vec buffer with zeros to simulate unmapped pages */
    if (vec && len > 0) {
        size_t page_count = (len + PAGE_SIZE - 1) / PAGE_SIZE; // Round up to page count
        unsigned char *fake_vec = kzalloc(page_count, GFP_KERNEL); // Allocate and zero a fake vector

        if (fake_vec) {
            if (copy_to_user(vec, fake_vec, page_count)) {
                pr_warn("mincore hook: Failed to copy fake vec to user\n");
            }
            kfree(fake_vec);
        }
    }

    /* Set return value to 0, simulating successful execution with all pages as unmapped */
    args->ret = 0;
    // args->done = 1; // Skip the actual mincore call (not available in hook_fargs4_t)
}

uint64_t mincore_counts = 0;

void before_mincore_1(hook_fargs4_t *args, void *udata)
{
    /* Count the occurrences if needed */
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    pr_info("hook_chain_1 before mincore task: %llx, count: %llx\n", args->local.data0, *pcount);
}

void after_mincore_1(hook_fargs4_t *args, void *udata)
{
    pr_info("hook_chain_1 after mincore task: %llx\n", args->local.data0);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-syscall-hook-demo init ..., args: %s\n", margs);

    hook_err_t err = HOOK_NO_ERR;

    if (!margs) {
        pr_warn("no args specified, skip hook\n");
        return 0;
    }

    if (!strcmp("function_pointer_hook", margs)) {
        pr_info("function pointer hook ...");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_mincore, 3, before_mincore_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_mincore, 3, before_mincore_1, after_mincore_1, &mincore_counts);
    } else if (!strcmp("inline_hook", margs)) {
        pr_info("inline hook ...");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_mincore, 3, before_mincore_0, 0, 0);
    } else {
        pr_warn("unknown args: %s\n", margs);
        return 0;
    }

out:
    if (err) {
        pr_err("hook mincore error: %d\n", err);
    } else {
        pr_info("hook mincore success\n");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("syscall_hook control, args: %s\n", args);
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    pr_info("kpm-syscall-hook-demo exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscall(__NR_mincore, before_mincore_0, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscall(__NR_mincore, before_mincore_0, 0);
        fp_unhook_syscall(__NR_mincore, before_mincore_1, after_mincore_1);
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);
