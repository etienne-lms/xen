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

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/sizes.h>
#include <xen/bitops.h>

#include <asm/smccc.h>
#include <asm/event.h>
#include <asm/ffa.h>
#include <asm/regs.h>

/* Error codes */
#define FFA_RET_OK			0
#define FFA_RET_NOT_SUPPORTED		-1
#define FFA_RET_INVALID_PARAMETERS	-2
#define FFA_RET_NO_MEMORY		-3
#define FFA_RET_BUSY			-4
#define FFA_RET_INTERRUPTED		-5
#define FFA_RET_DENIED			-6
#define FFA_RET_RETRY			-7
#define FFA_RET_ABORTED			-8

/* FFA_VERSION helpers */
#define FFA_VERSION_MAJOR		_AC(1,U)
#define FFA_VERSION_MAJOR_SHIFT		_AC(16,U)
#define FFA_VERSION_MAJOR_MASK		_AC(0x7FFF,U)
#define FFA_VERSION_MINOR		_AC(0,U)
#define FFA_VERSION_MINOR_SHIFT		_AC(0,U)
#define FFA_VERSION_MINOR_MASK		_AC(0xFFFF,U)
#define MAKE_FFA_VERSION(major, minor)	\
	((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
	 ((minor) & FFA_VERSION_MINOR_MASK))

#define FFA_MIN_VERSION		MAKE_FFA_VERSION(1, 0)
#define FFA_MY_VERSION		MAKE_FFA_VERSION(FFA_VERSION_MAJOR, \
						 FFA_VERSION_MINOR)


/* Memory attributes: Normal memory, Write-Back cacheable, Inner shareable */
#define FFA_NORMAL_MEM_REG_ATTR		_AC(0x2f,U)

/* Memory access permissions: Read-write */
#define FFA_MEM_ACC_RW			_AC(0x2,U)

/* Clear memory before mapping in receiver */
#define FFA_MEMORY_REGION_FLAG_CLEAR		BIT(0, U)
/* Relayer may time slice this operation */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE	BIT(1, U)
/* Clear memory after receiver relinquishes it */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH	BIT(2, U)

/* Share memory transaction */
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE (_AC(1,U) << 3)
/* Relayer must choose the alignment boundary */
#define FFA_MEMORY_REGION_FLAG_ANY_ALIGNMENT	_AC(0,U)

#define FFA_HANDLE_INVALID		_AC(0xffffffffffffffff,ULL)

/* Function IDs */
#define FFA_ERROR			_AC(0x84000060,U)
#define FFA_SUCCESS_32			_AC(0x84000061,U)
#define FFA_SUCCESS_64			_AC(0xC4000061,U)
#define FFA_INTERRUPT			_AC(0x84000062,U)
#define FFA_VERSION			_AC(0x84000063,U)
#define FFA_FEATURES			_AC(0x84000064,U)
#define FFA_RX_RELEASE			_AC(0x84000065,U)
#define FFA_RXTX_MAP_32			_AC(0x84000066,U)
#define FFA_RXTX_MAP_64			_AC(0xC4000066,U)
#define FFA_RXTX_UNMAP			_AC(0x84000067,U)
#define FFA_PARTITION_INFO_GET		_AC(0x84000068,U)
#define FFA_ID_GET			_AC(0x84000069,U)
#define FFA_MSG_WAIT			_AC(0x8400006B,U)
#define FFA_MSG_YIELD			_AC(0x8400006C,U)
#define FFA_MSG_RUN			_AC(0x8400006D,U)
#define FFA_MSG_SEND			_AC(0x8400006E,U)
#define FFA_MSG_SEND_DIRECT_REQ_32	_AC(0x8400006F,U)
#define FFA_MSG_SEND_DIRECT_REQ_64	_AC(0xC400006F,U)
#define FFA_MSG_SEND_DIRECT_RESP_32	_AC(0x84000070,U)
#define FFA_MSG_SEND_DIRECT_RESP_64	_AC(0xC4000070,U)
#define FFA_MSG_POLL			_AC(0x8400006A,U)
#define FFA_MEM_DONATE_32		_AC(0x84000071,U)
#define FFA_MEM_DONATE_64		_AC(0xC4000071,U)
#define FFA_MEM_LEND_32			_AC(0x84000072,U)
#define FFA_MEM_LEND_64			_AC(0xC4000072,U)
#define FFA_MEM_SHARE_32		_AC(0x84000073,U)
#define FFA_MEM_SHARE_64		_AC(0xC4000073,U)
#define FFA_MEM_RETRIEVE_REQ_32		_AC(0x84000074,U)
#define FFA_MEM_RETRIEVE_REQ_64		_AC(0xC4000074,U)
#define FFA_MEM_RETRIEVE_RESP		_AC(0x84000075,U)
#define FFA_MEM_RELINQUISH		_AC(0x84000076,U)
#define FFA_MEM_RECLAIM			_AC(0x84000077,U)
#define FFA_MEM_FRAG_RX			_AC(0x8400007A,U)
#define FFA_MEM_FRAG_TX			_AC(0x8400007B,U)
#define FFA_SECONDARY_EP_REGISTER_64	_AC(0xC4000084,U)

#define FFA_MSG_FLAG_FRAMEWORK		BIT(31, U)
#define FFA_MSG_TYPE_MASK		_AC(0xFF,U);
#define FFA_MSG_PSCI			_AC(0x0,U)
#define FFA_MSG_SEND_VM_CREATED		_AC(0x4,U)
#define FFA_MSG_RESP_VM_CREATED		_AC(0x5,U)
#define FFA_MSG_SEND_VM_DESTROYED	_AC(0x6,U)
#define FFA_MSG_RESP_VM_DESTROYED	_AC(0x7,U)

/* Endpoint RX/TX descriptor */
struct ffa_endpoint_rxtx_descriptor {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_range_count;
    uint32_t tx_range_count;
};

/* Partition information descriptor */
struct ffa_partition_info {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

/* Constituent memory region descriptor */
struct ffa_address_range {
	uint64_t address;
	uint32_t page_count;
	uint32_t reserved;
};

/* Composite memory region descriptor */
struct ffa_mem_region {
	uint32_t total_page_count;
	uint32_t address_range_count;
	uint64_t reserved;
	struct ffa_address_range address_range_array[];
};

/* Memory access permissions descriptor */
struct ffa_mem_access_perm {
	uint16_t endpoint_id;
	uint8_t perm;
	uint8_t flags;
};

/* Endpoint memory access descriptor */
struct ffa_mem_access {
	struct ffa_mem_access_perm access_perm;
	uint32_t region_offs;
	uint64_t reserved;
};

/* Lend, donate or share memory transaction descriptor */
struct ffa_mem_transaction {
	uint16_t sender_id;
	uint8_t mem_reg_attr;
	uint8_t reserved0;
	uint32_t flags;
	uint64_t global_handle;
	uint64_t tag;
	uint32_t reserved1;
	uint32_t mem_access_count;
	struct ffa_mem_access mem_access_array[];
};

struct ffa_ctx {
    void *rx;
    void *tx;
    struct page_info *rx_pg;
    struct page_info *tx_pg;
    unsigned int page_count;
    bool tx_is_mine;
    bool interrupted;
};

struct ffa_shm_mem {
    struct list_head list;
    uint16_t sender_id;
    uint16_t ep_id;     /* endpoint, the one lending */
    uint64_t handle;    /* FFA_HANDLE_INVALID if not set yet */
    unsigned int page_count;
    struct page_info *pages[];
};

/*
 * Our rx/rx buffer shared with the SPMC
 */
static uint32_t ffa_version;
static void *ffa_rx;
static void *ffa_tx;
static unsigned int ffa_page_count;
static spinlock_t ffa_buffer_lock = SPIN_LOCK_UNLOCKED;

static struct list_head ffa_mem_list = LIST_HEAD_INIT(ffa_mem_list);
static spinlock_t ffa_mem_list_lock = SPIN_LOCK_UNLOCKED;

static uint64_t reg_pair_to_64(uint32_t reg0, uint32_t reg1)
{
    return (uint64_t)reg0 << 32 | reg1;
}

static void reg_pair_from_64(uint32_t *reg0, uint32_t *reg1, uint64_t val)
{
    *reg0 = val >> 32;
    *reg1 = val;
}

static bool ffa_get_version(uint32_t *vers)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_VERSION, .a1 = FFA_MY_VERSION,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);
    if ( resp.a0 == FFA_RET_NOT_SUPPORTED )
    {
        printk(XENLOG_ERR "ffa: FFA_VERSION returned not supported\n");
        return false;
    }

    *vers = resp.a0;
    return true;
}

static uint32_t ffa_rxtx_map(register_t tx_addr, register_t rx_addr,
                             uint32_t page_count)
{
    const struct arm_smccc_1_2_regs arg = {
#ifdef CONFIG_ARM_64
        .a0 = FFA_RXTX_MAP_64,
#endif
#ifdef CONFIG_ARM_32
        .a0 = FFA_RXTX_MAP_32,
#endif
	.a1 = tx_addr, .a2 = rx_addr,
        .a3 = page_count,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    return FFA_RET_OK;
}

static uint32_t ffa_rxtx_unmap(uint16_t vm_id)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_RXTX_UNMAP, .a1 = vm_id,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    return FFA_RET_OK;
}

static uint32_t ffa_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                       uint32_t w4, uint32_t w5,
                                       uint32_t *count)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET, .a1 = w1, .a2 = w2, .a3 = w3, .a4 = w4,
        .a5 = w5,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    *count = resp.a2;

    return FFA_RET_OK;
}

static uint32_t ffa_rx_release(void)
{
    const struct arm_smccc_1_2_regs arg = { .a0 = FFA_RX_RELEASE, };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    return FFA_RET_OK;
}

static uint32_t ffa_mem_share(uint32_t tot_len, uint32_t frag_len,
                              register_t addr, uint32_t pg_count,
                              uint64_t *handle)
{
    struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MEM_SHARE_32, .a1 = tot_len, .a2 = frag_len, .a3 = addr,
        .a4 = pg_count,
    };
    struct arm_smccc_1_2_regs resp;

    /*
     * For arm64 we must use 64-bit calling convention if the buffer isn't
     * passed in our tx buffer.
     */
    if (sizeof(addr) > 4 && addr)
        arg.a0 = FFA_MEM_SHARE_64;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    *handle = reg_pair_to_64(resp.a3, resp.a2);
    return FFA_RET_OK;
}

static uint32_t ffa_mem_reclaim(uint32_t handle_lo, uint32_t handle_hi,
                                uint32_t flags)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MEM_RECLAIM, .a1 = handle_lo, .a2 = handle_hi, .a3 = flags,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    if ( resp.a0 == FFA_ERROR )
    {
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    }

    return FFA_RET_OK;
}

static u16 get_vm_id(struct domain *d)
{
    /* +1 since 0 is reserved for the hypervisor in FF-A */
    return d->domain_id + 1;
}

static uint32_t handle_rxtx_map(uint32_t fid, register_t tx_addr,
                                register_t rx_addr, uint32_t page_count)
{
    uint32_t ret = FFA_RET_NOT_SUPPORTED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    struct page_info *tx_pg;
    struct page_info *rx_pg;
    p2m_type_t t;
    void *rx;
    void *tx;

    if ( !smccc_is_conv_64(fid) )
    {
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    /* For now to keep things simple, only deal with a single page */
    if ( page_count != 1 )
        return FFA_RET_NOT_SUPPORTED;

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gaddr_to_gfn(tx_addr), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_NOT_SUPPORTED;
    /* Only normal RAM for now */
    if (t != p2m_ram_rw)
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gaddr_to_gfn(rx_addr), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_put_tx_pg;
    /* Only normal RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_rx_pg;

    tx = __map_domain_page_global(tx_pg);
    if ( !tx )
        goto err_put_rx_pg;

    rx = __map_domain_page_global(rx_pg);
    if ( !rx )
        goto err_unmap_tx;

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = 1;
    ctx->tx_is_mine = true;
    return FFA_RET_OK;

err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);
    return ret;
}

static uint32_t handle_rxtx_unmap(void)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    uint32_t ret;

    if ( !ctx-> rx )
        return FFA_RET_INVALID_PARAMETERS;

    ret = ffa_rxtx_unmap(get_vm_id(d));
    if ( ret )
        return ret;

    unmap_domain_page_global(ctx->rx);
    unmap_domain_page_global(ctx->tx);
    put_page(ctx->rx_pg);
    put_page(ctx->tx_pg);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->tx_is_mine = false;

    return FFA_RET_OK;
}

static uint32_t handle_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                          uint32_t w4, uint32_t w5,
                                          uint32_t *count)
{
    uint32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    size_t sz;

    if ( !ffa_page_count )
        return FFA_RET_DENIED;

    spin_lock(&ffa_buffer_lock);
    if ( !ctx->page_count || !ctx->tx_is_mine )
        goto out;
    ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count);
    if ( ret )
        goto out;
    sz = *count * sizeof(struct ffa_partition_info);
    memcpy(ctx->rx, ffa_rx, sz);
    ffa_rx_release();
    ctx->tx_is_mine = false;
out:
    spin_unlock(&ffa_buffer_lock);

    return ret;
}

static uint32_t handle_rx_release(void)
{
    uint32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;

    spin_lock(&ffa_buffer_lock);
    if ( !ctx->page_count || ctx->tx_is_mine )
        goto out;
    ret = FFA_RET_OK;
    ctx->tx_is_mine = true;
out:
    spin_unlock(&ffa_buffer_lock);

    return ret;
}

static void handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct arm_smccc_1_2_regs resp = { };
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    uint32_t src_dst;
    uint64_t mask;

    if ( smccc_is_conv_64(fid) )
        mask = 0xffffffffffffffff;
    else
        mask = 0xffffffff;

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != get_vm_id(d) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    arg.a1 = src_dst;
    arg.a2 = get_user_reg(regs, 2) & mask;
    arg.a3 = get_user_reg(regs, 3) & mask;
    arg.a4 = get_user_reg(regs, 4) & mask;
    arg.a5 = get_user_reg(regs, 5) & mask;
    arg.a6 = get_user_reg(regs, 6) & mask;
    arg.a7 = get_user_reg(regs, 7) & mask;

    while (true) {
        arm_smccc_1_2_smc(&arg, &resp);

        switch ( resp.a0 )
        {
        case FFA_INTERRUPT:
            ctx->interrupted = true;
            goto out;
        case FFA_ERROR:
        case FFA_SUCCESS_32:
        case FFA_SUCCESS_64:
        case FFA_MSG_SEND_DIRECT_RESP_32:
        case FFA_MSG_SEND_DIRECT_RESP_64:
            goto out;
        default:
            /* Bad fid, report back. */
            memset(&arg, 0, sizeof(arg));
            arg.a0 = FFA_ERROR;
            arg.a1 = src_dst;
            arg.a2 = FFA_RET_NOT_SUPPORTED;
            continue;
        }
    }

out:
    set_user_reg(regs, 0, resp.a0);
    set_user_reg(regs, 2, resp.a2 & mask);
    set_user_reg(regs, 1, resp.a1 & mask);
    set_user_reg(regs, 3, resp.a3 & mask);
    set_user_reg(regs, 4, resp.a4 & mask);
    set_user_reg(regs, 5, resp.a5 & mask);
    set_user_reg(regs, 6, resp.a6 & mask);
    set_user_reg(regs, 7, resp.a7 & mask);
}

static int get_shm_pages(struct domain *d, struct ffa_shm_mem *shm,
                         struct ffa_mem_region *region_descr)
{
    unsigned int pg_idx = 0;
    unsigned int n;
    unsigned int m;
    unsigned long gfn;
    p2m_type_t t;

    for ( n = 0; n < region_descr->address_range_count; n++ )
    {
        for ( m = 0; m < region_descr->address_range_array[n].page_count; m++ )
        {
            if ( pg_idx >= shm->page_count )
                return FFA_RET_INVALID_PARAMETERS;

            gfn = gaddr_to_gfn(region_descr->address_range_array[n].address +
                               m * PAGE_SIZE);
            shm->pages[pg_idx] = get_page_from_gfn(d, gfn, &t, P2M_ALLOC);
            if ( !shm->pages[pg_idx] )
                return FFA_RET_DENIED;
            pg_idx++;
            /* Only normal RAM for now */
            if (t != p2m_ram_rw)
                return FFA_RET_DENIED;
        }
    }

    if ( pg_idx != shm->page_count )
        return FFA_RET_INVALID_PARAMETERS;

    return FFA_RET_OK;
}

static void put_shm_pages(struct ffa_shm_mem *shm)
{
    unsigned int n;

    for ( n = 0; n < shm->page_count && shm->pages[n]; n++ )
    {
        put_page(shm->pages[n]);
        shm->pages[n] = NULL;
    }
}

static void init_range(struct ffa_address_range *addr_range,
                       paddr_t pa)
{
    memset(addr_range, 0, sizeof(*addr_range));
    addr_range->address = pa;
    addr_range->page_count = 1;
}

static int share_shm(struct ffa_shm_mem *shm)
{
    struct ffa_mem_transaction *descr = ffa_tx;
    struct ffa_mem_region *region_descr;
    struct ffa_address_range *addr_range;
    paddr_t pa;
    unsigned int n;
    uint32_t tot_len;

    memset(descr, 0, sizeof(*descr));
    descr->sender_id = shm->sender_id;
    descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
    descr->mem_access_count = 1;

    region_descr = (void *)&descr->mem_access_array[1];

    memset(descr->mem_access_array, 0, sizeof(descr->mem_access_array[0]));
    descr->mem_access_array[0].access_perm.endpoint_id = shm->ep_id;
    descr->mem_access_array[0].access_perm.perm = FFA_MEM_ACC_RW;
    descr->mem_access_array[0].region_offs = (vaddr_t)region_descr -
                                             (vaddr_t)descr;

    memset(region_descr, 0, sizeof(*region_descr));
    region_descr->total_page_count = shm->page_count;
    region_descr->address_range_count = 1;

    tot_len = (vaddr_t)&region_descr->address_range_array[1] - ((vaddr_t)descr);
    addr_range = region_descr->address_range_array;
    init_range(addr_range, page_to_maddr(shm->pages[0]));

    for (n = 1; n < shm->page_count; n++)
    {
        pa = page_to_maddr(shm->pages[n]);
        if ( addr_range->address + addr_range->page_count * PAGE_SIZE == pa)
        {
            addr_range->page_count++;
            continue;
        }
        tot_len += sizeof(*addr_range);
        if (tot_len > ffa_page_count * PAGE_SIZE)
            return FFA_RET_NOT_SUPPORTED;
        region_descr->address_range_count++;
        addr_range++;
        init_range(addr_range, pa);
    }

    return ffa_mem_share(tot_len, tot_len, 0, 0, &shm->handle);
}

static int handle_mem_share(uint32_t tot_len, uint32_t frag_len,
                            uint64_t addr, uint32_t page_count,
                            uint32_t *handle_hi, uint32_t *handle_lo)
{
    struct ffa_mem_region *region_descr;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    struct ffa_mem_transaction *descr;
    struct ffa_shm_mem *shm = NULL;
    int ret = FFA_RET_DENIED;

    /*
     * We're only accepting memory transaction descriptors via the rx/tx
     * buffer.
     */
    if ( addr )
            return FFA_RET_NOT_SUPPORTED;

    spin_lock(&ffa_buffer_lock);

    /*
     * Keep it simple, no fragmentation and make sure everything fits in
     * the TX buffer.
     */
    if ( tot_len != frag_len || tot_len > ffa_page_count * PAGE_SIZE ||
         tot_len > ctx->page_count * PAGE_SIZE )
        goto out;

    if ( tot_len < sizeof(struct ffa_mem_transaction) )
        goto out;

    /*
     * Copy it to our TX buffer since we can trust the SPMC to not modify
     * our TX buffer.
     */
    memcpy(ffa_tx, ctx->tx, tot_len);
    descr = ffa_tx;

    if ( descr->sender_id != get_vm_id(d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    if ( descr->mem_reg_attr != FFA_NORMAL_MEM_REG_ATTR )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    /* Only supposed to share this with OP-TEE so one should be the number */
    if ( descr->mem_access_count != 1 )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }
    /* Check that it fits in the copied data */
    if ( sizeof(*descr) + sizeof(struct ffa_mem_access) > tot_len )
        goto out;

    if ( descr->mem_access_array[0].access_perm.perm != FFA_MEM_ACC_RW )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out;
    }

    /*
     * Check that the Composite memory region descriptor fits in the copied
     * data.
     */
    if ( sizeof(*region_descr) + descr->mem_access_array[0].region_offs >
         tot_len )
        goto out;
    region_descr = (void *)((uint8_t *)descr +
                            descr->mem_access_array[0].region_offs);
    if ( sizeof(*region_descr) + descr->mem_access_array[0].region_offs +
         region_descr->address_range_count *
            sizeof(struct ffa_address_range) > tot_len)
        goto out;

    shm = xzalloc_flex_struct(struct ffa_shm_mem, pages,
                              region_descr->total_page_count);
    if ( !shm )
    {
        ret = FFA_RET_NO_MEMORY;
        goto out;
    }
    shm->sender_id = descr->sender_id;
    shm->ep_id = descr->mem_access_array[0].access_perm.endpoint_id;
    shm->page_count = region_descr->total_page_count;
    shm->handle = FFA_HANDLE_INVALID;

    ret = get_shm_pages(d, shm, region_descr);
    if ( ret )
        goto out;

    /* Note that our tx buffer is overwritten by share_shm() */
    ret = share_shm(shm);
    if ( ret )
        goto out;

    spin_lock(&ffa_mem_list_lock);
    list_add_tail(&shm->list, &ffa_mem_list);
    spin_unlock(&ffa_mem_list_lock);

    reg_pair_from_64(handle_hi, handle_lo, shm->handle);

out:
    if ( ret && shm )
    {
        put_shm_pages(shm);
        xfree(shm);
    }
    spin_unlock(&ffa_buffer_lock);

    return ret;
}

static int handle_mem_reclaim(uint64_t handle, uint32_t flags)
{
    struct ffa_shm_mem *shm;
    uint32_t handle_hi;
    uint32_t handle_lo;
    int ret;

    spin_lock(&ffa_mem_list_lock);
    list_for_each_entry(shm, &ffa_mem_list, list)
    {
        if (shm->handle == handle)
            goto found_it;
    }
    shm = NULL;
found_it:
    spin_unlock(&ffa_mem_list_lock);

    if ( !shm )
        return FFA_RET_INVALID_PARAMETERS;

    reg_pair_from_64(&handle_hi, &handle_lo, handle);
    ret = ffa_mem_reclaim(handle_lo, handle_hi, flags);
    if (ret)
        return ret;

    spin_lock(&ffa_mem_list_lock);
    list_del(&shm->list);
    spin_unlock(&ffa_mem_list_lock);

    put_shm_pages(shm);
    xfree(shm);

    return ret;
}

static void set_regs(struct cpu_user_regs *regs, register_t v0, register_t v1,
                     register_t v2, register_t v3, register_t v4, register_t v5,
                     register_t v6, register_t v7)
{
        set_user_reg(regs, 0, v0);
        set_user_reg(regs, 1, v1);
        set_user_reg(regs, 2, v2);
        set_user_reg(regs, 3, v3);
        set_user_reg(regs, 4, v4);
        set_user_reg(regs, 5, v5);
        set_user_reg(regs, 6, v6);
        set_user_reg(regs, 7, v7);
}

static void set_regs_error(struct cpu_user_regs *regs, uint32_t error_code)
{
    set_regs(regs, FFA_ERROR, 0, error_code, 0, 0, 0, 0, 0);
}

static void set_regs_success(struct cpu_user_regs *regs, uint32_t w2,
                             uint32_t w3)
{
    set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, 0, 0, 0, 0);
}

bool ffa_handle_call(struct cpu_user_regs *regs, uint32_t fid)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.ffa;
    uint32_t count;
    uint32_t e;
    uint32_t handle_hi;
    uint32_t handle_lo;

    if ( !ctx )
        return false;

    switch ( fid )
    {
    case FFA_VERSION:
        set_regs(regs, ffa_version, 0, 0, 0, 0, 0, 0, 0);
        return true;
    case FFA_ID_GET:
        set_regs_success(regs, get_vm_id(d), 0);
        return true;
    case FFA_RXTX_MAP_32:
#ifdef CONFIG_ARM_64
    case FFA_RXTX_MAP_64:
#endif
        e = handle_rxtx_map(fid, get_user_reg(regs, 1), get_user_reg(regs, 2),
                            get_user_reg(regs, 3));
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_RXTX_UNMAP:
        e = handle_rxtx_unmap();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_PARTITION_INFO_GET:
        e = handle_partition_info_get(get_user_reg(regs, 1),
                                      get_user_reg(regs, 2),
                                      get_user_reg(regs, 3),
                                      get_user_reg(regs, 4),
                                      get_user_reg(regs, 5), &count);
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, count, 0);
        return true;
    case FFA_RX_RELEASE:
        e = handle_rx_release();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_MSG_SEND_DIRECT_REQ_32:
#ifdef CONFIG_ARM_64
    case FFA_MSG_SEND_DIRECT_REQ_64:
#endif
        handle_msg_send_direct_req(regs, fid);
        return true;
    case FFA_MEM_SHARE_32:
#ifdef CONFIG_ARM_64
    case FFA_MEM_SHARE_64:
#endif
        e = handle_mem_share(get_user_reg(regs, 1), get_user_reg(regs, 2),
                             get_user_reg(regs, 3), get_user_reg(regs, 4),
                             &handle_hi, &handle_lo);
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, handle_lo, handle_hi);
        return true;
    case FFA_MEM_RECLAIM:
        e = handle_mem_reclaim(reg_pair_to_64(get_user_reg(regs, 2),
                                              get_user_reg(regs, 1)),
                               get_user_reg(regs, 3));
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;

    default:
        printk(XENLOG_ERR "ffa: unhandled fid 0x%x\n", fid);
        return false;
    }
}

int ffa_domain_init(struct domain *d)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MSG_SEND_DIRECT_REQ_32,
        .a2 = FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_SEND_VM_CREATED,
	.a5 = get_vm_id(d),
    };
    struct arm_smccc_1_2_regs resp;
    struct ffa_ctx *ctx;

    if ( !ffa_version )
        return 0;

    ctx = xzalloc(struct ffa_ctx);
    if ( !ctx )
        return -ENOMEM;

    arm_smccc_1_2_smc(&arg, &resp);
    if (resp.a0 != FFA_MSG_SEND_DIRECT_RESP_32 ||
        resp.a2 != (FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_RESP_VM_CREATED) ||
        resp.a3) {
        XFREE(ctx);
        return -ENOMEM;
    }

    d->arch.ffa = ctx;

    return 0;
}

int ffa_relinquish_resources(struct domain *d)
{    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MSG_SEND_DIRECT_REQ_32,
        .a2 = FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_SEND_VM_DESTROYED,
	.a5 = get_vm_id(d),
    };
    struct arm_smccc_1_2_regs resp;
    struct ffa_ctx *ctx = d->arch.ffa;

    if ( !ctx )
        return 0;

    arm_smccc_1_2_smc(&arg, &resp);
    if (resp.a0 != FFA_MSG_SEND_DIRECT_RESP_32 ||
        resp.a2 != (FFA_MSG_FLAG_FRAMEWORK | FFA_MSG_RESP_VM_DESTROYED) ||
        resp.a3) {
        printk(XENLOG_ERR "ffa: Failed to report destruction of vm_id %u: "
                          "a0 0x%lx, a2 0x%lx, a3 0x%lx\n",
                          get_vm_id(d), resp.a0, resp.a2, resp.a3);
    }

    XFREE(d->arch.ffa);

    return 0;
}

static int __init ffa_init(void)
{
    uint32_t vers;
    uint32_t e;

    /*
     * psci_init_smccc() updates this value with what's reported by EL-3
     * or secure world.
     */
    if ( smccc_ver < ARM_SMCCC_VERSION_1_2 )
    {
        printk(XENLOG_ERR
               "ffa: unsupported SMCCC version %#x (need at least %#x)\n",
               smccc_ver, ARM_SMCCC_VERSION_1_2);
        return 0;
    }

    if ( !ffa_get_version(&vers) )
        return 0;

    if ( vers < FFA_MIN_VERSION || vers > FFA_MY_VERSION )
    {
        printk(XENLOG_ERR "ffa: Incompatible version %#x found\n", vers);
        return 0;
    }

    printk(XENLOG_ERR "ffa: vers 0x%x\n", vers);

    ffa_rx = alloc_xenheap_pages(0, 0);
    if ( !ffa_rx )
        return 0;

    ffa_tx = alloc_xenheap_pages(0, 0);
    if ( !ffa_tx )
        goto err_free_ffa_rx;

    e = ffa_rxtx_map(__pa(ffa_tx), __pa(ffa_rx), 1);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to map rxtx: error %d\n", (int)e);
        goto err_free_ffa_tx;
    }
    ffa_page_count = 1;
    ffa_version = vers;
    return 0;

err_free_ffa_tx:
    free_xenheap_pages(ffa_tx, 0);
    ffa_tx = NULL;
err_free_ffa_rx:
    free_xenheap_pages(ffa_rx, 0);
    ffa_rx = NULL;
    return 0;
}

__initcall(ffa_init);
