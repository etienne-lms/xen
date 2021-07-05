/*
 * xen/arch/arm/ffa.c
 *
 * Arm Firmware Framework for ARMv8-A(FFA) mediator
 *
 * Copyright (C) 2021  Linaro Limited
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __ASM_ARM_FFA_H__
#define __ASM_ARM_FFA_H__

#include <xen/const.h>

#include <asm/smccc.h>
#include <asm/types.h>

#define FFA_FNUM_MIN_VALUE              _AC(0x60,U)
#define FFA_FNUM_MAX_VALUE              _AC(0x84,U)

static inline bool is_ffa_fid(uint32_t fid)
{
    uint32_t fn = fid & ARM_SMCCC_FUNC_MASK;

    return fn >= FFA_FNUM_MIN_VALUE && fn <= FFA_FNUM_MAX_VALUE;
}

#ifdef CONFIG_FFA
#ifdef CONFIG_ARM_32
#define FFA_NR_FUNCS    8
#endif
#ifdef CONFIG_ARM_64
#define FFA_NR_FUNCS    11
#endif

bool ffa_handle_call(struct cpu_user_regs *regs, uint32_t fid);
int ffa_domain_init(struct domain *d);
int ffa_relinquish_resources(struct domain *d);
#else
#define FFA_NR_FUNCS    0

static inline bool ffa_handle_call(struct cpu_user_regs *regs, uint32_t fid)
{
    return false;
}

static inline int ffa_domain_init(struct domain *d)
{
    return 0;
}

static inline int ffa_relinquish_resources(struct domain *d)
{
    return 0;
}
#endif

#endif /*__ASM_ARM_FFA_H__*/
