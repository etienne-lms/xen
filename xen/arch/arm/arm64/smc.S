/*
 * xen/arch/arm/arm64/smc.S
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
 * void __arm_smccc_1_0_smc(register_t a0, register_t a1, register_t a2,
 *                          register_t a3, register_t a4, register_t a5,
 *                          register_t a6, register_t a7,
 *                          struct arm_smccc_res *res)
 */
ENTRY(__arm_smccc_1_0_smc)
        smc     #0
        ldr     x4, [sp]
        cbz     x4, 1f          /* No need to store the result */
        stp     x0, x1, [x4, #SMCCC_RES_a0]
        stp     x2, x3, [x4, #SMCCC_RES_a2]
1:
        ret


/*
 * void arm_smccc_1_2_smc(const struct arm_smccc_1_2_regs *args,
 *                        struct arm_smccc_1_2_regs *res)
 */
ENTRY(arm_smccc_1_2_smc)
    /* Save `res` and free a GPR that won't be clobbered */
    stp     x1, x19, [sp, #-16]!

    /* Ensure `args` won't be clobbered while loading regs in next step */
    mov	x19, x0

    /* Load the registers x0 - x17 from the struct arm_smccc_1_2_regs */
    ldp	x0, x1, [x19, #0]
    ldp	x2, x3, [x19, #16]
    ldp	x4, x5, [x19, #32]
    ldp	x6, x7, [x19, #48]
    ldp	x8, x9, [x19, #64]
    ldp	x10, x11, [x19, #80]
    ldp	x12, x13, [x19, #96]
    ldp	x14, x15, [x19, #112]
    ldp	x16, x17, [x19, #128]

    smc #0

    /* Load the `res` from the stack */
    ldr	x19, [sp]

    /* Store the registers x0 - x17 into the result structure */
    stp	x0, x1, [x19, #0]
    stp	x2, x3, [x19, #16]
    stp	x4, x5, [x19, #32]
    stp	x6, x7, [x19, #48]
    stp	x8, x9, [x19, #64]
    stp	x10, x11, [x19, #80]
    stp	x12, x13, [x19, #96]
    stp	x14, x15, [x19, #112]
    stp	x16, x17, [x19, #128]

    /* Restore original x19 */
    ldp     xzr, x19, [sp], #16
    ret
