/*
 * This file contains kasan initialization code for ARM64.
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) "kasan: " fmt
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/sched/task.h>
#include <linux/memblock.h>
#include <linux/start_kernel.h>
#include <linux/mm.h>

#include <asm/mmu_context.h>
#include <asm/kernel-pgtable.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>

static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);

/*
 * The p*d_populate functions call virt_to_phys implicitly so they can't be used
 * directly on kernel symbols (bm_p*d). All the early functions are called too
 * early to use lm_alias so __p*d_populate functions must be used to populate
 * with the physical address from __pa_symbol.
 */

static void __init kasan_early_pte_populate(pmd_t *pmdp, unsigned long addr,
					unsigned long end)
{
	pte_t *ptep;
	unsigned long next;

	if (pmd_none(READ_ONCE(*pmdp)))
		__pmd_populate(pmdp, __pa_symbol(kasan_zero_pte), PMD_TYPE_TABLE);

	ptep = pte_offset_kimg(pmdp, addr);
	do {
		next = addr + PAGE_SIZE;
		set_pte(ptep, pfn_pte(sym_to_pfn(kasan_zero_page),
					PAGE_KERNEL));
	} while (ptep++, addr = next, addr != end && pte_none(READ_ONCE(*ptep)));
}

static void __init kasan_early_pmd_populate(pud_t *pudp,
					unsigned long addr,
					unsigned long end)
{
	pmd_t *pmdp;
	unsigned long next;

	if (pud_none(READ_ONCE(*pudp)))
		__pud_populate(pudp, __pa_symbol(kasan_zero_pmd), PMD_TYPE_TABLE);

	pmdp = pmd_offset_kimg(pudp, addr);
	do {
		next = pmd_addr_end(addr, end);
		kasan_early_pte_populate(pmdp, addr, next);
	} while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));
}

static void __init kasan_early_pud_populate(pgd_t *pgdp,
					unsigned long addr,
					unsigned long end)
{
	pud_t *pudp;
	unsigned long next;

	if (pgd_none(READ_ONCE(*pgdp)))
		__pgd_populate(pgdp, __pa_symbol(kasan_zero_pud), PUD_TYPE_TABLE);

	pudp = pud_offset_kimg(pgdp, addr);
	do {
		next = pud_addr_end(addr, end);
		kasan_early_pmd_populate(pudp, addr, next);
	} while (pudp++, addr = next, addr != end && pud_none(READ_ONCE(*pudp)));
}

static void __init kasan_map_early_shadow(void)
{
	unsigned long addr = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;
	unsigned long next;
	pgd_t *pgdp;

	pgdp = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		kasan_early_pud_populate(pgdp, addr, next);
	} while (pgdp++, addr = next, addr != end);
}

asmlinkage void __init kasan_early_init(void)
{
	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END - (1UL << 61));
	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_SIZE));
	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));
	kasan_map_early_shadow();
}

/*
 * Copy the current shadow region into a new pgdir.
 */
void __init kasan_copy_shadow(pgd_t *pgdir)
{
	pgd_t *pgdp, *pgd_newp, *pgd_endp;

	pgdp = pgd_offset_k(KASAN_SHADOW_START);
	pgd_endp = pgd_offset_k(KASAN_SHADOW_END);
	pgd_newp = pgd_offset_raw(pgdir, KASAN_SHADOW_START);
	do {
		set_pgd(pgd_newp, READ_ONCE(*pgdp));
	} while (pgdp++, pgd_newp++, pgdp != pgd_endp);
}

static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	/*
	 * Remove references to kasan page tables from
	 * swapper_pg_dir. pgd_clear() can't be used
	 * here because it's nop on 2,3-level pagetable setups
	 */
	for (; start < end; start += PGDIR_SIZE)
		set_pgd(pgd_offset_k(start), __pgd(0));
}

void __init kasan_init(void)
{
	u64 kimg_shadow_start, kimg_shadow_end;
	u64 mod_shadow_start, mod_shadow_end;
	struct memblock_region *reg;
	int i;

	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text);
	kimg_shadow_end = (u64)kasan_mem_to_shadow(_end);

	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);

	/*
	 * We are going to perform proper setup of shadow memory.
	 * At first we should unmap early shadow (clear_pgds() call bellow).
	 * However, instrumented code couldn't execute without shadow memory.
	 * tmp_pg_dir used to keep early shadow mapped until full shadow
	 * setup will be finished.
	 */
	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
	dsb(ishst);
	cpu_replace_ttbr1(lm_alias(tmp_pg_dir));

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	vmemmap_populate(kimg_shadow_start, kimg_shadow_end,
			 pfn_to_nid(virt_to_pfn(lm_alias(_text))));

	/*
	 * vmemmap_populate() has populated the shadow region that covers the
	 * kernel image with SWAPPER_BLOCK_SIZE mappings, so we have to round
	 * the start and end addresses to SWAPPER_BLOCK_SIZE as well, to prevent
	 * kasan_populate_zero_shadow() from replacing the page table entries
	 * (PMD or PTE) at the edges of the shadow region for the kernel
	 * image.
	 */
	kimg_shadow_start = round_down(kimg_shadow_start, SWAPPER_BLOCK_SIZE);
	kimg_shadow_end = round_up(kimg_shadow_end, SWAPPER_BLOCK_SIZE);

	kasan_populate_zero_shadow((void *)KASAN_SHADOW_START,
				   (void *)mod_shadow_start);
	kasan_populate_zero_shadow((void *)kimg_shadow_end,
				   kasan_mem_to_shadow((void *)PAGE_OFFSET));

	if (kimg_shadow_start > mod_shadow_end)
		kasan_populate_zero_shadow((void *)mod_shadow_end,
					   (void *)kimg_shadow_start);

	for_each_memblock(memory, reg) {
		void *start = (void *)__phys_to_virt(reg->base);
		void *end = (void *)__phys_to_virt(reg->base + reg->size);

		if (start >= end)
			break;

		vmemmap_populate((unsigned long)kasan_mem_to_shadow(start),
				(unsigned long)kasan_mem_to_shadow(end),
				pfn_to_nid(virt_to_pfn(start)));
	}

	/*
	 * KAsan may reuse the contents of kasan_zero_pte directly, so we
	 * should make sure that it maps the zero page read-only.
	 */
	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(&kasan_zero_pte[i],
			pfn_pte(sym_to_pfn(kasan_zero_page), PAGE_KERNEL_RO));

	memset(kasan_zero_page, 0, PAGE_SIZE);
	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));

	/* At this point kasan is fully initialized. Enable error messages */
	init_task.kasan_depth = 0;
	pr_info("KernelAddressSanitizer initialized\n");
}
