#include "include/klog.h"
#include "include/common_data.h"
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/mmdebug.h>

struct mm_struct *mm = NULL;

asm (
        "__cpu_flush_kern_tlb_range:\n\t"
        "dsb     sy\n\t"
        "lsr     x0, x0, #12\n\t"                  // align address
        "lsr     x1, x1, #12\n\t"
"1:      tlbi    vaae1is, x0\n\t"                     // TLB invalidate by address
        "add     x0, x0, #1\n\t"
        "cmp     x0, x1\n\t"
        "b.lo    1b\n\t"
        "dsb     sy\n\t"
        "isb\n\t"
        "ret\n\t"
);

#define pte_valid(pte)		(!!(pte_val(pte) & PTE_VALID))
static inline pte_t clear_pte_bit(pte_t pte, pgprot_t prot)
{
	pte_val(pte) &= ~pgprot_val(prot);
	return pte;
}

static inline pte_t set_pte_bit(pte_t pte, pgprot_t prot)
{
	pte_val(pte) |= pgprot_val(prot);
	return pte;
}

static pte_t *get_pte(unsigned long addr)
{
	pgd_t *pgdp = NULL;
	pud_t *pudp = NULL;
	pmd_t *pmdp = NULL;
    pte_t *ptep = NULL;

    struct mm_struct init_mm = {0};

    if (!mm) {
        mm = (struct mm_struct *)find_func("init_mm");
    }
    init_mm = *mm;

	pgdp = pgd_offset_k(addr);
	if (pgd_none(*pgdp)) {
		logerror("failed get pgdp for %p\n", (void *)addr);
		return NULL;
	}
	
	pudp = pud_offset(pgdp, addr);
	if (pud_none(*pudp)) {
        logerror("failed get pudp for %p\n", (void *)addr);
		return NULL;
	}
	
	pmdp = pmd_offset(pudp, addr);
	if (pmd_none(*pmdp)) {
		logerror("failed get pmdp for %p\n", (void *)addr);
		return NULL;
	}
	
	ptep = pte_offset_kernel(pmdp, addr);
	if (!pte_valid(*ptep)) {
		logerror("failed get pte for %p\n", (void *)addr);
		return NULL;
	}
    return ptep;
}

#define pte_user_exec(pte)	(!(pte_val(pte) & PTE_UXN))

static inline void set_pte_aatt(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	pte_t old_pte;
    void (*__sync_icache_dcache_ptr)(pte_t pteval) = find_func("__sync_icache_dcache");

	if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
		(*__sync_icache_dcache_ptr)(pte);

	/*
	 * If the existing pte is valid, check for potential race with
	 * hardware updates of the pte (ptep_set_access_flags safely changes
	 * valid ptes without going through an invalid entry).
	 */
	old_pte = (*ptep);
	// if (IS_ENABLED(CONFIG_DEBUG_VM) && pte_valid(old_pte) && pte_valid(pte) &&
	//    (mm == current->active_mm || atomic_read(&mm->mm_users) > 1)) {
	// 	VM_WARN_ONCE(!pte_young(pte),
	// 		     "%s: racy access flag clearing: 0x%016llx -> 0x%016llx",
	// 		     __func__, pte_val(old_pte), pte_val(pte));
	// 	VM_WARN_ONCE(pte_write(old_pte) && !pte_dirty(pte),
	// 		     "%s: racy dirty state clearing: 0x%016llx -> 0x%016llx",
	// 		     __func__, pte_val(old_pte), pte_val(pte));
	// }

	set_pte(ptep, pte);
}

int hook_write_word(void *addr, uint32_t word)
{
    pte_t origin_pte, pte, *ptep = NULL;

    ptep = get_pte((unsigned long)addr);
    if (!ptep)
        return -1;
    origin_pte = (pte = *ptep);

	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
    set_pte_aatt(mm, (unsigned long)addr, ptep, pte);
    // flush_tlb_kernel_range((unsigned long)addr, (unsigned long)(addr + PAGE_SIZE));

    memcpy(addr, &word, sizeof(uint32_t));
    
    set_pte_aatt(mm, (unsigned long)addr, ptep, origin_pte);
    // flush_tlb_kernel_range((unsigned long)addr, (unsigned long)(addr + PAGE_SIZE));
    return 0;
}