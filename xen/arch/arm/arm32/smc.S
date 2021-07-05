/*
 * xen/arch/arm/arm32/smc.S
 *
 * Wrapper for Secure Monitors Calls
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/asm_defns.h>
#include <asm/macros.h>

/*
 * void arm_smccc_1_2_smc(const struct arm_smccc_1_2_regs *args,
 *                        struct arm_smccc_1_2_regs *res)
 */
ENTRY(arm_smccc_1_2_smc)
    push    {r4-r7} 
    push    {r0, lr}
    ldm     r0, {r0-r7}
    smc     #0
    pop     {r12, lr}
    stm     r12, {r0-r7}
    pop     {r4-r7}
    bx      lr
