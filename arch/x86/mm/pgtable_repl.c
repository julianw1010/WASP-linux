#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/pgtable_repl.h>
#include <asm/tlbflush.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/io.h>

#ifdef CONFIG_PGTABLE_REPLICATION

atomic_t total_cr3_writes = ATOMIC_INIT(0);
atomic_t replica_hits = ATOMIC_INIT(0);
atomic_t primary_hits = ATOMIC_INIT(0);

atomic_t repl_pte_sets = ATOMIC_INIT(0);
atomic_t repl_pmd_sets = ATOMIC_INIT(0);
atomic_t repl_pud_sets = ATOMIC_INIT(0);
atomic_t repl_p4d_sets = ATOMIC_INIT(0);
atomic_t repl_pgd_sets = ATOMIC_INIT(0);

atomic_t repl_pte_clears = ATOMIC_INIT(0);
atomic_t repl_pmd_clears = ATOMIC_INIT(0);
atomic_t repl_pud_clears = ATOMIC_INIT(0);
atomic_t repl_p4d_clears = ATOMIC_INIT(0);
atomic_t repl_pgd_clears = ATOMIC_INIT(0);

atomic_t repl_pte_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_pmd_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_pud_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_p4d_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_pgd_gets_aggregated = ATOMIC_INIT(0);

atomic_t repl_prot_commits = ATOMIC_INIT(0);
atomic_t repl_ptep_get_and_clears = ATOMIC_INIT(0);
atomic_t repl_ptep_get_and_clears_aggregated = ATOMIC_INIT(0);

int sysctl_mitosis_auto_enable = -1;
int sysctl_mitosis_inherit = 1;


struct cr3_switch_info {
    struct mm_struct *mm;
    pgd_t *original_pgd;
};

static struct page *get_replica_for_node(struct page *base, int target_node);
static bool link_page_replicas(struct page **pages, int count);

static DEFINE_MUTEX(global_repl_mutex);


unsigned long pgtable_repl_read_cr3(void)
{
	return __native_read_cr3();
}


void pgtable_repl_write_cr3(unsigned long cr3)
{
	native_write_cr3(cr3);
}

static bool link_page_replicas(struct page **pages, int count)
{
    int i;
    struct page *p;

    if (count < 2)
        return true;

    /* Link into circular list */
    for (i = 0; i < count - 1; i++) {
        WRITE_ONCE(pages[i]->replica, pages[i + 1]);
    }
    WRITE_ONCE(pages[count - 1]->replica, pages[0]);

    smp_mb();

    /* Validate the circular list */
    p = pages[0];
    for (i = 0; i < count; i++) {
        if (!p->replica)
            return false;  /* Link failed */
        p = p->replica;
    }

    if (p != pages[0])
        return false;  /* Not circular */

    return true;
}


static struct page *get_replica_for_node(struct page *base, int target_node)
{
    struct page *page;
    struct page *next;
    int iterations = 0;

    if (!base)
        return NULL;

    /* Check if base is already on target node */
    if (page_to_nid(base) == target_node)
        return base;

    page = READ_ONCE(base->replica);
    if (!page)
        return NULL;  /* No replicas - race with disable */

    /* Walk the circular list looking for target node */
    while (page != base) {
        if (page_to_nid(page) == target_node)
            return page;

        next = READ_ONCE(page->replica);
        if (!next)
            return NULL;  /* Chain broken - race with disable */
        page = next;

        if (++iterations >= MAX_NUMNODES)
            return NULL;  /* Corrupted chain */
    }

    /* Target node not found in replica chain */
    return NULL;
}


static int alloc_pte_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i, j;
    int base_node;
    int expected_count;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    /* Snapshot expected count before iterating */
    expected_count = nodes_weight(mm->repl_pgd_nodes);
    if (expected_count < 2)
        return -EAGAIN;  /* Race with disable */

    base_node = page_to_nid(base_page);
    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, mm->repl_pgd_nodes) {
        struct page *new_page;
        struct ptdesc *pt;

        if (i == base_node)
            continue;

        new_page = alloc_pages_node(i,
            GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE |
            __GFP_HIGH | __GFP_MEMALLOC, 0);

        if (!new_page)
            goto fail_cleanup;

        if (page_to_nid(new_page) != i) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pt = page_ptdesc(new_page);
        if (!pagetable_pte_ctor(pt)) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pages[*count] = new_page;
        (*count)++;
    }

    /* Verify count matches - detects race with disable */
    if (*count != expected_count)
        goto fail_cleanup;

    return 0;

fail_cleanup:
    for (j = 1; j < *count; j++) {
        struct ptdesc *pt = page_ptdesc(pages[j]);
        pagetable_dtor(pt);
        __free_page(pages[j]);
    }
    *count = 0;
    return -EAGAIN;
}

static int alloc_pmd_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i, j;
    int base_node;
    int expected_count;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    expected_count = nodes_weight(mm->repl_pgd_nodes);
    if (expected_count < 2)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, mm->repl_pgd_nodes) {
        struct page *new_page;
        struct ptdesc *pt;

        if (i == base_node)
            continue;

        new_page = alloc_pages_node(i,
            GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE |
            __GFP_HIGH | __GFP_MEMALLOC, 0);

        if (!new_page)
            goto fail_cleanup;

        if (page_to_nid(new_page) != i) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pt = page_ptdesc(new_page);
        if (!pagetable_pmd_ctor(pt)) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pages[*count] = new_page;
        (*count)++;
    }

    if (*count != expected_count)
        goto fail_cleanup;

    return 0;

fail_cleanup:
    for (j = 1; j < *count; j++) {
        struct ptdesc *pt = page_ptdesc(pages[j]);
        pagetable_dtor(pt);
        __free_page(pages[j]);
    }
    *count = 0;
    return -EAGAIN;
}

static int alloc_pud_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i, j;
    int base_node;
    int expected_count;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    expected_count = nodes_weight(mm->repl_pgd_nodes);
    if (expected_count < 2)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, mm->repl_pgd_nodes) {
        struct page *new_page;
        struct ptdesc *pt;

        if (i == base_node)
            continue;

        new_page = alloc_pages_node(i,
            GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE |
            __GFP_HIGH | __GFP_MEMALLOC, 0);

        if (!new_page)
            goto fail_cleanup;

        if (page_to_nid(new_page) != i) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pt = page_ptdesc(new_page);
        pagetable_pud_ctor(pt);

        pages[*count] = new_page;
        (*count)++;
    }

    if (*count != expected_count)
        goto fail_cleanup;

    return 0;

fail_cleanup:
    for (j = 1; j < *count; j++) {
        struct ptdesc *pt = page_ptdesc(pages[j]);
        pagetable_dtor(pt);
        __free_page(pages[j]);
    }
    *count = 0;
    return -EAGAIN;
}

static int alloc_p4d_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i, j;
    int base_node;
    int expected_count;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    expected_count = nodes_weight(mm->repl_pgd_nodes);
    if (expected_count < 2)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, mm->repl_pgd_nodes) {
        struct page *new_page;
        struct ptdesc *pt;

        if (i == base_node)
            continue;

        new_page = alloc_pages_node(i,
            GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE |
            __GFP_HIGH | __GFP_MEMALLOC, 0);

        if (!new_page)
            goto fail_cleanup;

        if (page_to_nid(new_page) != i) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pt = page_ptdesc(new_page);
        pagetable_p4d_ctor(pt);

        pages[*count] = new_page;
        (*count)++;
    }

    if (*count != expected_count)
        goto fail_cleanup;

    return 0;

fail_cleanup:
    for (j = 1; j < *count; j++) {
        struct ptdesc *pt = page_ptdesc(pages[j]);
        pagetable_dtor(pt);
        __free_page(pages[j]);
    }
    *count = 0;
    return -EAGAIN;
}

static int alloc_pgd_replicas(struct page *base_page, nodemask_t nodes,
                              struct page **pages, int *count)
{
    int i, j;
    int base_node;
    int expected_count;

    if (!base_page || !pages || !count)
        return -EINVAL;

    expected_count = nodes_weight(nodes);
    if (expected_count < 2)
        return -EINVAL;

    base_node = page_to_nid(base_page);
    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes) {
        struct page *new_page;
        struct ptdesc *pt;

        if (i == base_node)
            continue;

        new_page = alloc_pages_node(i,
            GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE |
            __GFP_HIGH | __GFP_MEMALLOC, 0);

        if (!new_page)
            goto fail_cleanup;

        if (page_to_nid(new_page) != i) {
            __free_page(new_page);
            goto fail_cleanup;
        }

        pt = page_ptdesc(new_page);
        pagetable_pgd_ctor(pt);

        pages[*count] = new_page;
        (*count)++;
    }

    if (*count != expected_count)
        goto fail_cleanup;

    return 0;

fail_cleanup:
    for (j = 1; j < *count; j++) {
        struct ptdesc *pt = page_ptdesc(pages[j]);
        pagetable_dtor(pt);
        __free_page(pages[j]);
    }
    *count = 0;
    return -ENOMEM;
}

void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval)
{
    struct page *pte_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    struct mm_struct *mm;

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_set_pte(ptep, pteval);
        return;
    }

    mm = current->mm;
    
    /* Replication not enabled - use native */
    if (!mm->repl_pgd_enabled) {
        native_set_pte(ptep, pteval);
        return;
    }

    pte_page = virt_to_page(ptep);
    repl = READ_ONCE(pte_page->replica);

    /* Create replicas on-demand if missing */
    if (!repl) {
        pgtable_repl_alloc_pte(mm, page_to_pfn(pte_page));
        repl = READ_ONCE(pte_page->replica);
        if (!repl)
            BUG();
    }

    /* Track replicated set operation */
    atomic_inc(&repl_pte_sets);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;

    /* Walk ALL replicas in the circular list and update each */
    cur_page = pte_page;
    do {
        void *page_addr = page_address(cur_page);
        pte_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pte_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, pteval);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pte_page);

    smp_wmb();
}

void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
    struct page *parent_page, *child_base_page = NULL;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    unsigned long entry_val = pmd_val(pmdval);
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child = pmd_present(pmdval) && !pmd_trans_huge(pmdval) && entry_val != 0;
    struct mm_struct *mm;

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_set_pmd(pmdp, pmdval);
        return;
    }

    mm = current->mm;
    
    /* Replication not enabled - use native */
    if (!mm->repl_pgd_enabled) {
        native_set_pmd(pmdp, pmdval);
        return;
    }

    parent_page = virt_to_page(pmdp);
    repl = READ_ONCE(parent_page->replica);

    /* Create parent replicas on-demand if missing */
    if (!repl) {
        pgtable_repl_alloc_pmd(mm, page_to_pfn(parent_page));
        repl = READ_ONCE(parent_page->replica);
        if (!repl)
            BUG();
    }

    /* Track replicated set operation */
    atomic_inc(&repl_pmd_sets);

    /* Find the base page of the child (PTE) if this PMD points to one */
    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        if (!child_phys || !pfn_valid(child_phys >> PAGE_SHIFT))
            BUG();

        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        if (!child_base_page)
            BUG();

        /* Create child replicas on-demand if missing */
        if (!READ_ONCE(child_base_page->replica)) {
            pgtable_repl_alloc_pte(mm, page_to_pfn(child_base_page));
            if (!READ_ONCE(child_base_page->replica))
                BUG();
        }
    }

    offset = ((unsigned long)pmdp) & ~PAGE_MASK;

    /* Walk ALL replicas and write node-local child pointers */
    struct page *cur_page = parent_page;
    do {
        void *page_addr = page_address(cur_page);
        pmd_t *replica_entry;
        unsigned long node_val;
        int node;

        if (!page_addr)
            BUG();

        node = page_to_nid(cur_page);
        replica_entry = (pmd_t *)(page_addr + offset);

        if (has_child) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            void *node_child_addr;
            unsigned long node_child_phys;

            if (!node_local_child)
                BUG();
            if (page_to_nid(node_local_child) != node)
                BUG();

            node_child_addr = page_address(node_local_child);
            if (!node_child_addr)
                BUG();

            node_child_phys = __pa(node_child_addr);
            if (!node_child_phys)
                BUG();
            if (!pfn_valid(node_child_phys >> PAGE_SHIFT))
                BUG();

            node_val = node_child_phys | (entry_val & ~pfn_mask);
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pmd(node_val));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != parent_page);

    smp_wmb();
}

void pgtable_repl_set_pud(pud_t *pudp, pud_t pudval)
{
    struct page *parent_page, *child_base_page = NULL;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    unsigned long entry_val = pud_val(pudval);
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child = pud_present(pudval) && !pud_trans_huge(pudval) && entry_val != 0;
    struct mm_struct *mm;

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_set_pud(pudp, pudval);
        return;
    }

    mm = current->mm;
    
    /* Replication not enabled - use native */
    if (!mm->repl_pgd_enabled) {
        native_set_pud(pudp, pudval);
        return;
    }

    parent_page = virt_to_page(pudp);
    repl = READ_ONCE(parent_page->replica);

    /* Create parent replicas on-demand if missing */
    if (!repl) {
        pgtable_repl_alloc_pud(mm, page_to_pfn(parent_page));
        repl = READ_ONCE(parent_page->replica);
        if (!repl)
            BUG();
    }

    /* Track replicated set operation */
    atomic_inc(&repl_pud_sets);

    /* Find the base page of the child (PMD) if this PUD points to one */
    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        if (!child_phys || !pfn_valid(child_phys >> PAGE_SHIFT))
            BUG();

        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        if (!child_base_page)
            BUG();

        /* Create child replicas on-demand if missing */
        if (!READ_ONCE(child_base_page->replica)) {
            pgtable_repl_alloc_pmd(mm, page_to_pfn(child_base_page));
            if (!READ_ONCE(child_base_page->replica))
                BUG();
        }
    }

    offset = ((unsigned long)pudp) & ~PAGE_MASK;

    /* Walk ALL replicas and write node-local child pointers */
    struct page *cur_page = parent_page;
    do {
        void *page_addr = page_address(cur_page);
        pud_t *replica_entry;
        unsigned long node_val;
        int node;

        if (!page_addr)
            BUG();

        node = page_to_nid(cur_page);
        replica_entry = (pud_t *)(page_addr + offset);

        if (has_child) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            void *node_child_addr;
            unsigned long node_child_phys;

            if (!node_local_child)
                BUG();
            if (page_to_nid(node_local_child) != node)
                BUG();

            node_child_addr = page_address(node_local_child);
            if (!node_child_addr)
                BUG();

            node_child_phys = __pa(node_child_addr);
            if (!node_child_phys)
                BUG();
            if (!pfn_valid(node_child_phys >> PAGE_SHIFT))
                BUG();

            node_val = node_child_phys | (entry_val & ~pfn_mask);
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pud(node_val));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != parent_page);

    smp_wmb();
}

void pgtable_repl_set_p4d(p4d_t *p4dp, p4d_t p4dval)
{
    struct page *parent_page, *child_base_page = NULL;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    unsigned long entry_val = p4d_val(p4dval);
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child = p4d_present(p4dval) && entry_val != 0;
    struct mm_struct *mm;

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    mm = current->mm;
    
    /* Replication not enabled - use native */
    if (!mm->repl_pgd_enabled) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    parent_page = virt_to_page(p4dp);
    repl = READ_ONCE(parent_page->replica);

    /* Create parent replicas on-demand if missing */
    if (!repl) {
        pgtable_repl_alloc_p4d(mm, page_to_pfn(parent_page));
        repl = READ_ONCE(parent_page->replica);
        if (!repl)
            BUG();
    }

    /* Track replicated set operation */
    atomic_inc(&repl_p4d_sets);

    /* Find the base page of the child (PUD) if this P4D points to one */
    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        if (!child_phys || !pfn_valid(child_phys >> PAGE_SHIFT))
            BUG();

        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        if (!child_base_page)
            BUG();

        /* Create child replicas on-demand if missing */
        if (!READ_ONCE(child_base_page->replica)) {
            pgtable_repl_alloc_pud(mm, page_to_pfn(child_base_page));
            if (!READ_ONCE(child_base_page->replica))
                BUG();
        }
    }

    offset = ((unsigned long)p4dp) & ~PAGE_MASK;

    /* Walk ALL replicas and write node-local child pointers */
    struct page *cur_page = parent_page;
    do {
        void *page_addr = page_address(cur_page);
        p4d_t *replica_entry;
        unsigned long node_val;
        int node;

        if (!page_addr)
            BUG();

        node = page_to_nid(cur_page);
        replica_entry = (p4d_t *)(page_addr + offset);

        if (has_child) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            void *node_child_addr;
            unsigned long node_child_phys;

            if (!node_local_child)
                BUG();
            if (page_to_nid(node_local_child) != node)
                BUG();

            node_child_addr = page_address(node_local_child);
            if (!node_child_addr)
                BUG();

            node_child_phys = __pa(node_child_addr);
            if (!node_child_phys)
                BUG();
            if (!pfn_valid(node_child_phys >> PAGE_SHIFT))
                BUG();

            node_val = node_child_phys | (entry_val & ~pfn_mask);
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __p4d(node_val));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != parent_page);

    smp_wmb();
}

void pgtable_repl_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
    struct page *parent_page, *child_base_page = NULL;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    unsigned long entry_val = pgd_val(pgdval);
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child = pgd_present(pgdval) && entry_val != 0;
    struct mm_struct *mm;

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_set_pgd(pgdp, pgdval);
        return;
    }

    mm = current->mm;
    
    /* Replication not enabled - use native */
    if (!mm->repl_pgd_enabled) {
        native_set_pgd(pgdp, pgdval);
        return;
    }

    parent_page = virt_to_page(pgdp);
    repl = READ_ONCE(parent_page->replica);

    /* PGD must have replicas if replication is enabled */
    if (!repl)
        BUG();

    /* Track replicated set operation */
    atomic_inc(&repl_pgd_sets);

    /* Find the base page of the child (P4D or PUD depending on LA57) */
    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        if (!child_phys || !pfn_valid(child_phys >> PAGE_SHIFT))
            BUG();

        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        if (!child_base_page)
            BUG();

        /* Create child replicas on-demand if missing */
        if (!READ_ONCE(child_base_page->replica)) {
            if (pgtable_l5_enabled()) {
                pgtable_repl_alloc_p4d(mm, page_to_pfn(child_base_page));
            } else {
                pgtable_repl_alloc_pud(mm, page_to_pfn(child_base_page));
            }
            if (!READ_ONCE(child_base_page->replica))
                BUG();
        }
    }

    offset = ((unsigned long)pgdp) & ~PAGE_MASK;

    /* Walk ALL PGD replicas and write node-local child pointers */
    struct page *cur_page = parent_page;
    do {
        void *page_addr = page_address(cur_page);
        pgd_t *replica_entry;
        unsigned long node_val;
        int node;

        if (!page_addr)
            BUG();

        node = page_to_nid(cur_page);
        replica_entry = (pgd_t *)(page_addr + offset);

        if (has_child) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            void *node_child_addr;
            unsigned long node_child_phys;

            if (!node_local_child)
                BUG();
            if (page_to_nid(node_local_child) != node)
                BUG();

            node_child_addr = page_address(node_local_child);
            if (!node_child_addr)
                BUG();

            node_child_phys = __pa(node_child_addr);
            if (!node_child_phys)
                BUG();
            if (!pfn_valid(node_child_phys >> PAGE_SHIFT))
                BUG();

            node_val = node_child_phys | (entry_val & ~pfn_mask);
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pgd(node_val));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != parent_page);

    smp_wmb();
}

pte_t pgtable_repl_get_pte(pte_t *ptep)
{
    struct mm_struct *mm = current ? current->mm : NULL;
    struct page *pte_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    pteval_t val;
    pteval_t original_val;

    val = pte_val(*ptep);
    original_val = val;

    if (!mm || !mm->repl_pgd_enabled)
        return (pte_t){ .pte = val };

    /* Don't aggregate for non-present or swap entries */
    if (!pte_present((pte_t){ .pte = val }))
        return (pte_t){ .pte = val };

    pte_page = virt_to_page(ptep);
    repl = READ_ONCE(pte_page->replica);

    if (!repl)
        return (pte_t){ .pte = val };

    offset = ((unsigned long)ptep) & ~PAGE_MASK;

    /* Walk the circular list and OR together all flags */
    cur_page = pte_page->replica;
    while (cur_page && cur_page != pte_page) {
        pte_t *replica_pte;
        void *page_addr = page_address(cur_page);

        if (!page_addr)
            break;

        replica_pte = (pte_t *)(page_addr + offset);
        val |= pte_val(*replica_pte);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            break;
    }

    /* Track if we actually aggregated different flags */
    if (val != original_val)
        atomic_inc(&repl_pte_gets_aggregated);

    return (pte_t){ .pte = val };
}

pmd_t pgtable_repl_get_pmd(pmd_t *pmdp)
{
    struct mm_struct *mm = current ? current->mm : NULL;
    struct page *pmd_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    pmdval_t val, flags, original_flags;

    val = pmd_val(*pmdp);

    if (!mm || !mm->repl_pgd_enabled)
        return __pmd(val);

    /* Only aggregate flags for huge PMDs (leaf entries with A/D bits) */
    if (!pmd_present(__pmd(val)) || !pmd_trans_huge(__pmd(val)))
        return __pmd(val);

    pmd_page = virt_to_page(pmdp);
    repl = READ_ONCE(pmd_page->replica);

    if (!repl)
        return __pmd(val);

    offset = ((unsigned long)pmdp) & ~PAGE_MASK;
    flags = pmd_flags(__pmd(val));
    original_flags = flags;

    /* Walk the circular list and OR together all flags */
    cur_page = pmd_page->replica;
    while (cur_page && cur_page != pmd_page) {
        pmd_t *replica_pmd;
        void *page_addr = page_address(cur_page);

        if (!page_addr)
            break;

        replica_pmd = (pmd_t *)(page_addr + offset);
        flags |= pmd_flags(*replica_pmd);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            break;
    }

    /* Track if we actually aggregated different flags */
    if (flags != original_flags)
        atomic_inc(&repl_pmd_gets_aggregated);

    /* Combine original PFN with aggregated flags */
    return __pmd((val & PTE_PFN_MASK) | flags);
}

pud_t pgtable_repl_get_pud(pud_t *pudp)
{
    struct mm_struct *mm = current ? current->mm : NULL;
    struct page *pud_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    pudval_t val, flags, original_flags;

    val = pud_val(*pudp);

    if (!mm || !mm->repl_pgd_enabled)
        return __pud(val);

    /* Only aggregate flags for huge PUDs (1GB leaf entries with A/D bits) */
    if (!pud_present(__pud(val)) || !pud_trans_huge(__pud(val)))
        return __pud(val);

    pud_page = virt_to_page(pudp);
    repl = READ_ONCE(pud_page->replica);

    if (!repl)
        return __pud(val);

    offset = ((unsigned long)pudp) & ~PAGE_MASK;
    flags = pud_flags(__pud(val));
    original_flags = flags;

    /* Walk the circular list and OR together all flags */
    cur_page = pud_page->replica;
    while (cur_page && cur_page != pud_page) {
        pud_t *replica_pud;
        void *page_addr = page_address(cur_page);

        if (!page_addr)
            break;

        replica_pud = (pud_t *)(page_addr + offset);
        flags |= pud_flags(*replica_pud);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            break;
    }

    /* Track if we actually aggregated different flags */
    if (flags != original_flags)
        atomic_inc(&repl_pud_gets_aggregated);

    /* Combine original PFN with aggregated flags */
    return __pud((val & PTE_PFN_MASK) | flags);
}

p4d_t pgtable_repl_get_p4d(p4d_t *p4dp)
{
    struct mm_struct *mm = current ? current->mm : NULL;
    struct page *p4d_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    p4dval_t val, flags, original_flags;

    val = p4d_val(*p4dp);

    if (!mm || !mm->repl_pgd_enabled)
        return __p4d(val);

    if (!p4d_present(__p4d(val)))
        return __p4d(val);

    p4d_page = virt_to_page(p4dp);
    repl = READ_ONCE(p4d_page->replica);

    if (!repl)
        return __p4d(val);

    offset = ((unsigned long)p4dp) & ~PAGE_MASK;
    flags = p4d_flags(__p4d(val));
    original_flags = flags;

    /* Walk the circular list and OR together all flags */
    cur_page = p4d_page->replica;
    while (cur_page && cur_page != p4d_page) {
        p4d_t *replica_p4d;
        void *page_addr = page_address(cur_page);

        if (!page_addr)
            break;

        replica_p4d = (p4d_t *)(page_addr + offset);
        flags |= p4d_flags(*replica_p4d);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            break;
    }

    /* Track if we actually aggregated different flags */
    if (flags != original_flags)
        atomic_inc(&repl_p4d_gets_aggregated);

    return __p4d((val & PTE_PFN_MASK) | flags);
}

pgd_t pgtable_repl_get_pgd(pgd_t *pgdp)
{
    struct mm_struct *mm = current ? current->mm : NULL;
    struct page *pgd_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    pgdval_t val, flags, original_flags;

    val = pgd_val(*pgdp);

    if (!mm || !mm->repl_pgd_enabled)
        return __pgd(val);

    if (!pgd_present(__pgd(val)))
        return __pgd(val);

    pgd_page = virt_to_page(mm->pgd);
    repl = READ_ONCE(pgd_page->replica);

    if (!repl)
        return __pgd(val);

    offset = ((unsigned long)pgdp) & ~PAGE_MASK;
    flags = pgd_flags(__pgd(val));
    original_flags = flags;

    /* Walk the circular list and OR together all flags */
    cur_page = pgd_page->replica;
    while (cur_page && cur_page != pgd_page) {
        pgd_t *replica_pgd;
        void *page_addr = page_address(cur_page);

        if (!page_addr)
            break;

        replica_pgd = (pgd_t *)(page_addr + offset);
        flags |= pgd_flags(*replica_pgd);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            break;
    }

    /* Track if we actually aggregated different flags */
    if (flags != original_flags)
        atomic_inc(&repl_pgd_gets_aggregated);

    return __pgd((val & PTE_PFN_MASK) | flags);
}


static void free_replica_chain(struct page *base_page)
{
    struct page *cur_page, *start_page;
    int iterations = 0;
    struct page *pages[MAX_NUMNODES];
    int page_count = 0;
    int i;

    if (!base_page || !base_page->replica)
        return;

    start_page = base_page;
    cur_page = base_page;

    
    do {
        if (!pfn_valid(page_to_pfn(cur_page)))
            BUG();
        if (page_count >= MAX_NUMNODES)
            BUG();

        pages[page_count++] = cur_page;
        cur_page = cur_page->replica;
        iterations++;

        if (iterations > MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != start_page);

    if (cur_page != start_page)
        BUG();

    
    for (i = 0; i < page_count; i++) {
        pages[i]->replica = NULL;
    }

    
    smp_mb();

    
    for (i = 1; i < page_count; i++) {
        struct ptdesc *pt = page_ptdesc(pages[i]);  
        
        
        pagetable_dtor(pt);  
        __free_page(pages[i]);
    }

    
    if (base_page->replica != NULL) {
        pr_err("MITOSIS ERROR: base_page->replica not NULL after free_replica_chain!\n");
        base_page->replica = NULL;
    }
}

typedef void (*replica_operation_fn)(void *base_addr, unsigned long offset, void *context);

void pgtable_repl_clear_pte(pte_t *ptep, struct mm_struct *mm)
{
    struct page *pte_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!ptep)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_pte_clear(mm, 0, ptep);
        return;
    }

    pte_page = virt_to_page(ptep);
    repl = READ_ONCE(pte_page->replica);

    /* If this page has no replicas, just use native */
    if (!repl) {
        native_pte_clear(mm, 0, ptep);
        return;
    }

    /* Track replicated clear operation */
    atomic_inc(&repl_pte_clears);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;

    /* Walk ALL replicas and clear each */
    cur_page = pte_page;
    do {
        void *page_addr = page_address(cur_page);
        pte_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pte_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, __pte(0));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pte_page);

    smp_wmb();
}

void pgtable_repl_clear_pmd(pmd_t *pmdp)
{
    struct page *pmd_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!pmdp)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_pmd_clear(pmdp);
        return;
    }

    pmd_page = virt_to_page(pmdp);
    repl = READ_ONCE(pmd_page->replica);

    /* If this page has no replicas, just use native */
    if (!repl) {
        native_pmd_clear(pmdp);
        return;
    }

    /* Track replicated clear operation */
    atomic_inc(&repl_pmd_clears);

    offset = ((unsigned long)pmdp) & ~PAGE_MASK;

    /* Walk ALL replicas and clear each */
    cur_page = pmd_page;
    do {
        void *page_addr = page_address(cur_page);
        pmd_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pmd_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, __pmd(0));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pmd_page);

    smp_wmb();
}

void pgtable_repl_clear_pud(pud_t *pudp)
{
    struct page *pud_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!pudp)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_pud_clear(pudp);
        return;
    }

    pud_page = virt_to_page(pudp);
    repl = READ_ONCE(pud_page->replica);

    /* If this page has no replicas, just use native */
    if (!repl) {
        native_pud_clear(pudp);
        return;
    }

    /* Track replicated clear operation */
    atomic_inc(&repl_pud_clears);

    offset = ((unsigned long)pudp) & ~PAGE_MASK;

    /* Walk ALL replicas and clear each */
    cur_page = pud_page;
    do {
        void *page_addr = page_address(cur_page);
        pud_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pud_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, __pud(0));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pud_page);

    smp_wmb();
}

void pgtable_repl_clear_p4d(p4d_t *p4dp)
{
    struct page *p4d_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!p4dp)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        native_p4d_clear(p4dp);
        return;
    }

    p4d_page = virt_to_page(p4dp);
    repl = READ_ONCE(p4d_page->replica);

    /* If this page has no replicas, just use native */
    if (!repl) {
        native_p4d_clear(p4dp);
        return;
    }

    /* Track replicated clear operation */
    atomic_inc(&repl_p4d_clears);

    offset = ((unsigned long)p4dp) & ~PAGE_MASK;

    /* Walk ALL replicas and clear each */
    cur_page = p4d_page;
    do {
        void *page_addr = page_address(cur_page);
        p4d_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (p4d_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, __p4d(0));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != p4d_page);

    smp_wmb();
}

void pgtable_repl_clear_pgd(pgd_t *pgdp)
{
    struct page *pgd_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!pgdp)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        if (pgtable_l5_enabled())
            native_pgd_clear(pgdp);
        return;
    }

    pgd_page = virt_to_page(pgdp);
    repl = READ_ONCE(pgd_page->replica);

    /* If this page has no replicas, just use native */
    if (!repl) {
        if (pgtable_l5_enabled())
            native_pgd_clear(pgdp);
        return;
    }

    /* Track replicated clear operation */
    atomic_inc(&repl_pgd_clears);

    offset = ((unsigned long)pgdp) & ~PAGE_MASK;

    /* Walk ALL replicas and clear each */
    cur_page = pgd_page;
    do {
        void *page_addr = page_address(cur_page);
        pgd_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pgd_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, __pgd(0));

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pgd_page);

    smp_wmb();
}

void pgtable_repl_ptep_modify_prot_commit(struct vm_area_struct *vma,
                                           unsigned long addr, pte_t *ptep,
                                           pte_t pte)
{
    struct page *pte_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;

    if (!vma || !ptep)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        WRITE_ONCE(*ptep, pte);
        smp_wmb();
        return;
    }

    pte_page = virt_to_page(ptep);
    repl = READ_ONCE(pte_page->replica);

    /* If this page has no replicas, just write directly */
    if (!repl) {
        WRITE_ONCE(*ptep, pte);
        smp_wmb();
        return;
    }

    /* Track replicated prot commit operation */
    atomic_inc(&repl_prot_commits);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;

    /* PTEs point to data pages - same value for all replicas */
    cur_page = pte_page;
    do {
        void *page_addr = page_address(cur_page);
        pte_t *replica_entry;

        if (!page_addr)
            BUG();

        replica_entry = (pte_t *)(page_addr + offset);
        WRITE_ONCE(*replica_entry, pte);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pte_page);

    smp_wmb();
}

static bool replicate_and_link_page(struct page *page, struct mm_struct *mm,
				    int (*alloc_fn)(struct page *, struct mm_struct *, struct page **, int *),
				    const char *level_name)
{
	struct page *pages[MAX_NUMNODES];
	int count = 0;
	void *src;
	int i;

	
	if (page->replica)
		return true;

	
	if (alloc_fn(page, mm, pages, &count) != 0) {
		pr_warn("MITOSIS WARNING: phase1 - failed to allocate %s replicas\n", level_name);
		return false;
	}

	
	if (!link_page_replicas(pages, count)) {
		pr_err("MITOSIS ERROR: phase1 - failed to link %s replicas\n", level_name);
		return false;
	}

	
	src = page_address(page);
	for (i = 1; i < count; i++) {
		void *dst = page_address(pages[i]);
		memcpy(dst, src, PAGE_SIZE);
		clflush_cache_range(dst, PAGE_SIZE);
	}

	return true;
}

static void replicate_existing_pagetables_phase1(struct mm_struct *mm)
{
	pgd_t *pgd = mm->pgd;
	int pgd_idx, p4d_idx, pud_idx, pmd_idx;

	if (!mm || !mm->repl_in_progress || !pgd)
		BUG();

	
	for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
		pgd_t *pgdp = &pgd[pgd_idx];
		pgd_t pgdval = READ_ONCE(*pgdp);
		p4d_t *p4d_base;
		unsigned long p4d_or_pud_phys;
		struct page *p4d_or_pud_page;

		if (pgd_none(pgdval) || !pgd_present(pgdval))
			continue;

		
		p4d_or_pud_phys = pgd_val(pgdval) & PTE_PFN_MASK;
		if (p4d_or_pud_phys && pfn_valid(p4d_or_pud_phys >> PAGE_SHIFT)) {
			p4d_or_pud_page = pfn_to_page(p4d_or_pud_phys >> PAGE_SHIFT);

			if (pgtable_l5_enabled()) {
				
				if (p4d_or_pud_page)
					replicate_and_link_page(p4d_or_pud_page, mm, alloc_p4d_replicas, "p4d");
			}
		}

		p4d_base = p4d_offset(pgdp, 0);
		if (!p4d_base)
			continue;

		for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
			p4d_t *p4dp = &p4d_base[p4d_idx];
			p4d_t p4dval = READ_ONCE(*p4dp);
			pud_t *pud_base;
			unsigned long pud_phys;
			struct page *pud_page;

			if (p4d_none(p4dval) || !p4d_present(p4dval))
				continue;

			
			pud_phys = p4d_val(p4dval) & PTE_PFN_MASK;
			if (pud_phys && pfn_valid(pud_phys >> PAGE_SHIFT)) {
				pud_page = pfn_to_page(pud_phys >> PAGE_SHIFT);
				if (pud_page)
					replicate_and_link_page(pud_page, mm, alloc_pud_replicas, "pud");
			}

			pud_base = pud_offset(p4dp, 0);
			if (!pud_base)
				continue;

			for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
				pud_t *pudp = &pud_base[pud_idx];
				pud_t pudval = READ_ONCE(*pudp);
				pmd_t *pmd_base;
				unsigned long pmd_phys;
				struct page *pmd_page;

				if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
					continue;

				
				pmd_phys = pud_val(pudval) & PTE_PFN_MASK;
				if (pmd_phys && pfn_valid(pmd_phys >> PAGE_SHIFT)) {
					pmd_page = pfn_to_page(pmd_phys >> PAGE_SHIFT);
					if (pmd_page)
						replicate_and_link_page(pmd_page, mm, alloc_pmd_replicas, "pmd");
				}

				pmd_base = pmd_offset(pudp, 0);
				if (!pmd_base)
					continue;

				for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
					pmd_t *pmdp = &pmd_base[pmd_idx];
					pmd_t pmdval = READ_ONCE(*pmdp);
					unsigned long pte_phys;
					struct page *pte_page;

					if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
						continue;

					
					pte_phys = pmd_val(pmdval) & PTE_PFN_MASK;
					if (pte_phys && pfn_valid(pte_phys >> PAGE_SHIFT)) {
						pte_page = pfn_to_page(pte_phys >> PAGE_SHIFT);
						if (pte_page)
							replicate_and_link_page(pte_page, mm, alloc_pte_replicas, "pte");
					}
				}
			}
		}
	}

	smp_mb();
}

static void replicate_existing_pagetables_phase2(struct mm_struct *mm)
{
	pgd_t *pgd = mm->pgd;
	struct page *pgd_page;
	int node, pgd_idx, p4d_idx, pud_idx, pmd_idx;

	if (!mm || !mm->repl_in_progress || !pgd)
		BUG();

	pgd_page = virt_to_page(pgd);
	if (!pgd_page->replica)
		BUG();

	
	for_each_node_mask(node, mm->repl_pgd_nodes) {
		pgd_t *node_pgd;
		struct page *node_pgd_page;

		
		node_pgd_page = get_replica_for_node(pgd_page, node);
		if (!node_pgd_page || page_to_nid(node_pgd_page) != node)
			BUG();

		node_pgd = page_address(node_pgd_page);
		if (!node_pgd)
			BUG();

		
		for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
			pgd_t pgdval = READ_ONCE(node_pgd[pgd_idx]);
			p4d_t *node_p4d_base;
			unsigned long child_phys;
			struct page *child_page;

			if (pgd_none(pgdval) || !pgd_present(pgdval))
				continue;

			
			if (pgtable_l5_enabled()) {
				
				child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
				if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
					child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
					if (child_page && child_page->replica) {
						struct page *local_child = get_replica_for_node(child_page, node);
						if (!local_child || page_to_nid(local_child) != node)
							BUG();
						
						p4d_t *local_p4d = page_address(local_child);
						if (!local_p4d)
							BUG();
						
						node_pgd[pgd_idx] = __pgd(__pa(local_p4d) | (pgd_val(pgdval) & ~PTE_PFN_MASK));
						pgdval = node_pgd[pgd_idx];
					}
				}
			} else {
			    
			    child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
			    if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
				child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
				if (child_page && child_page->replica) {
				    struct page *local_child = get_replica_for_node(child_page, node);
				    if (!local_child || page_to_nid(local_child) != node)
					BUG();
				    
				    pud_t *local_pud = page_address(local_child);
				    if (!local_pud)
					BUG();
				    
				    node_pgd[pgd_idx] = __pgd(__pa(local_pud) | (pgd_val(pgdval) & ~PTE_PFN_MASK));
				    pgdval = node_pgd[pgd_idx];
				} else if (child_page) {
				    
				    pr_warn("MITOSIS PHASE2: PGD[%d] for node %d: child PUD page has NO REPLICAS! pfn=%lx node=%d\n",
					    pgd_idx, node, page_to_pfn(child_page), page_to_nid(child_page));
				}
			    }
			}

			node_p4d_base = p4d_offset(&node_pgd[pgd_idx], 0);
			if (!node_p4d_base)
				continue;

			for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
				p4d_t p4dval = READ_ONCE(node_p4d_base[p4d_idx]);
				pud_t *node_pud_base;

				if (p4d_none(p4dval) || !p4d_present(p4dval))
					continue;

				
				child_phys = p4d_val(p4dval) & PTE_PFN_MASK;
				if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
					child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
					if (child_page && child_page->replica) {
						struct page *local_pud_page = get_replica_for_node(child_page, node);
						if (!local_pud_page || page_to_nid(local_pud_page) != node)
							BUG();
						
						pud_t *local_pud = page_address(local_pud_page);
						if (!local_pud)
							BUG();
						
						node_p4d_base[p4d_idx] = __p4d(__pa(local_pud) | (p4d_val(p4dval) & ~PTE_PFN_MASK));
						p4dval = node_p4d_base[p4d_idx];
					}
				}

				node_pud_base = pud_offset(&node_p4d_base[p4d_idx], 0);
				if (!node_pud_base || !virt_addr_valid(node_pud_base))
					continue;

				for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
					pud_t pudval = READ_ONCE(node_pud_base[pud_idx]);
					pmd_t *node_pmd_base;

					if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
						continue;

					
					child_phys = pud_val(pudval) & PTE_PFN_MASK;
					if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
						child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
						if (child_page && child_page->replica) {
							struct page *local_pmd_page = get_replica_for_node(child_page, node);
							if (!local_pmd_page || page_to_nid(local_pmd_page) != node)
								BUG();
							
							pmd_t *local_pmd = page_address(local_pmd_page);
							if (!local_pmd)
								BUG();
							
							node_pud_base[pud_idx] = __pud(__pa(local_pmd) | (pud_val(pudval) & ~PTE_PFN_MASK));
							pudval = node_pud_base[pud_idx];
						}
					}

					node_pmd_base = pmd_offset(&node_pud_base[pud_idx], 0);
					if (!node_pmd_base || !virt_addr_valid(node_pmd_base))
						continue;

					for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
						pmd_t pmdval = READ_ONCE(node_pmd_base[pmd_idx]);

						if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
							continue;

						
						child_phys = pmd_val(pmdval) & PTE_PFN_MASK;
						if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
							child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
							if (child_page && child_page->replica) {
								struct page *local_pte_page = get_replica_for_node(child_page, node);
								if (!local_pte_page || page_to_nid(local_pte_page) != node)
									BUG();
								
								pte_t *local_pte = page_address(local_pte_page);
								if (!local_pte)
									BUG();
								
								node_pmd_base[pmd_idx] = __pmd(__pa(local_pte) | (pmd_val(pmdval) & ~PTE_PFN_MASK));
							}
						}
					}
				}
			}
		}
	}

	smp_mb();
}

static void replicate_existing_pagetables(struct mm_struct *mm)
{
	if (!mm || !mm->repl_in_progress)
		BUG();

	
	replicate_existing_pagetables_phase1(mm);

	
	replicate_existing_pagetables_phase2(mm);

	
	flush_tlb_mm(mm);
	on_each_cpu_mask(mm_cpumask(mm), (void (*)(void *))__flush_tlb_all, NULL, 1);
	smp_mb();
}

int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes)
{
    struct page *pgd_pages[MAX_NUMNODES];
    struct page *base_page;
    pgd_t *base_pgd;
    int node, count = 0;
    int base_node;
    int ret = 0;
    int i;

    
    if (!mm || mm == &init_mm)
        return -EINVAL;

    if (nodes_weight(nodes) < 2)
        return -EINVAL;

    for_each_node_mask(node, nodes) {
        if (!node_online(node))
            return -EINVAL;
    }

    if (nodes_weight(nodes) > MAX_NUMNODES)
        return -EINVAL;

    
    mutex_lock(&global_repl_mutex);
    mutex_lock(&mm->repl_mutex);

    
    if (mm->repl_pgd_enabled) {
        if (nodes_equal(mm->repl_pgd_nodes, nodes)) {
            mutex_unlock(&mm->repl_mutex);
            mutex_unlock(&global_repl_mutex);
            return 0;
        }
        mutex_unlock(&mm->repl_mutex);
        mutex_unlock(&global_repl_mutex);
        return -EALREADY;
    }

    
    base_pgd = mm->pgd;
    if (!base_pgd || !virt_addr_valid(base_pgd)) {
        ret = -EINVAL;
        goto fail_unlock;
    }

    base_page = virt_to_page(base_pgd);
    if (!base_page) {
        ret = -EINVAL;
        goto fail_unlock;
    }

    base_node = page_to_nid(base_page);
    mm->original_pgd = base_pgd;
    smp_wmb();

    if (!node_isset(base_node, nodes))
        node_set(base_node, nodes);

    
    if (base_page->replica) {
        free_replica_chain(base_page);
        if (base_page->replica != NULL) {
            ret = -EFAULT;
            goto fail_unlock;
        }
    }

    base_page->replica = NULL;
    smp_wmb();

    
    memset(pgd_pages, 0, sizeof(pgd_pages));
    ret = alloc_pgd_replicas(base_page, nodes, pgd_pages, &count);
    if (ret)
        goto fail_unlock;

    if (count != nodes_weight(nodes)) {
        ret = -EFAULT;
        goto fail_free_pgds;
    }

    
    for (i = 0; i < count; i++) {
        bool found = false;
        
        if (!pgd_pages[i]) {
            ret = -EFAULT;
            goto fail_free_pgds;
        }
        
        for_each_node_mask(node, nodes) {
            if (page_to_nid(pgd_pages[i]) == node) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            ret = -EINVAL;
            goto fail_free_pgds;
        }
    }

    
    for (i = 0; i < count; i++)
        pgd_pages[i]->replica = NULL;
    smp_wmb();

    
    void *src_addr = page_address(pgd_pages[0]);
    if (!src_addr || src_addr != mm->pgd) {
        ret = -EINVAL;
        goto fail_free_pgds;
    }

    for (i = 1; i < count; i++) {
        void *dst_addr = page_address(pgd_pages[i]);
        if (!dst_addr) {
            ret = -EINVAL;
            goto fail_free_pgds;
        }
        memcpy(dst_addr, base_pgd, PTRS_PER_PGD * sizeof(pgd_t));
        clflush_cache_range(dst_addr, PAGE_SIZE);
    }
    smp_mb();

    
    if (count > 1) {
        if (!link_page_replicas(pgd_pages, count)) {
            ret = -EINVAL;
            goto fail_free_pgds;
        }
        
        if (base_page->replica == NULL) {
            ret = -EFAULT;
            goto fail_free_pgds;
        }
    }
    smp_mb();

    
    mm->repl_pgd_nodes = nodes;
    smp_wmb();
    
    if (!nodes_equal(mm->repl_pgd_nodes, nodes)) {
        ret = -EFAULT;
        goto fail_unlink_chain;
    }

    
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));

    for (i = 0; i < count; i++) {
        int node_id = page_to_nid(pgd_pages[i]);
        void *pgd_addr = page_address(pgd_pages[i]);
        
        if (!pgd_addr) {
            ret = -EFAULT;
            goto fail_unlink_chain;
        }
        
        mm->pgd_replicas[node_id] = pgd_addr;
        
        if (!mm->pgd_replicas[node_id]) {
            ret = -EFAULT;
            goto fail_unlink_chain;
        }
    }
    smp_wmb();
    
    
    mm->repl_in_progress = true;
    smp_wmb();

    
    for_each_node_mask(node, mm->repl_pgd_nodes) {
        pgd_t *replica_pgd = mm->pgd_replicas[node];
        int actual_node;

        if (!replica_pgd || !virt_addr_valid(replica_pgd)) {
            ret = -EFAULT;
            goto fail_disable;
        }

        actual_node = page_to_nid(virt_to_page(replica_pgd));
        if (actual_node != node) {
            ret = -EFAULT;
            goto fail_disable;
        }
    }

    bool found_primary = false;
    for (node = 0; node < MAX_NUMNODES; node++) {
        if (mm->pgd_replicas[node] == mm->pgd) {
            found_primary = true;
            break;
        }
    }

    if (!found_primary) {
        ret = -EFAULT;
        goto fail_disable;
    }

    if (mm->original_pgd != base_pgd) {
        ret = -EFAULT;
        goto fail_disable;
    }

    
    smp_store_release(&mm->repl_pgd_enabled, true);
    smp_mb();

    
    replicate_existing_pagetables(mm);

    
    mm->repl_in_progress = false;
    smp_wmb();

    
    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);

    
    flush_tlb_mm(mm);
    on_each_cpu_mask(mm_cpumask(mm), (void (*)(void *))__flush_tlb_all, NULL, 1);
    
    pr_info("MITOSIS: Enabled page table replication for mm %p\n", mm);
    
    /* Lazy CR3 switching: CPUs will switch to local replicas on next context switch */
    
    return 0;

fail_disable:
    mm->repl_pgd_enabled = false;
    mm->repl_in_progress = false;
    nodes_clear(mm->repl_pgd_nodes);
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    mm->original_pgd = NULL;
    smp_wmb();

fail_unlink_chain:
    if (base_page->replica) {
        for (i = 0; i < count; i++)
            pgd_pages[i]->replica = NULL;
        smp_wmb();
    }

fail_free_pgds:
    for (i = 1; i < count; i++) {
        if (pgd_pages[i]) {
            pgd_pages[i]->replica = NULL;
            smp_wmb();
            __free_page(pgd_pages[i]);
        }
    }
    
    if (base_page)
        base_page->replica = NULL;
    smp_wmb();

fail_unlock:
    mm->repl_pgd_enabled = false;         // FIRST: disable
    mm->repl_in_progress = false;
    smp_wmb();                            // Barrier before clearing state
    nodes_clear(mm->repl_pgd_nodes);      // THEN: clear nodes
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    mm->original_pgd = NULL;
    smp_wmb();

    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);

    return ret;
}

static void clear_replica_pointer_if_present(unsigned long phys_addr)
{
	struct page *page;

	if (!phys_addr || !pfn_valid(phys_addr >> PAGE_SHIFT))
		return;

	page = pfn_to_page(phys_addr >> PAGE_SHIFT);
	if (page && page->replica) {
		page->replica = NULL;
		smp_wmb();
	}
}

static void clear_replica_pointers_in_tree(struct mm_struct *mm)
{
	pgd_t *pgd = mm->pgd;
	struct page *pgd_page;
	int pgd_idx, p4d_idx, pud_idx, pmd_idx;

	if (!mm || !pgd) {
		pr_err("MITOSIS ERROR: clear_replica_pointers - NULL mm or pgd\n");
		return;
	}

	
	pgd_page = virt_to_page(pgd);
	if (pgd_page && pgd_page->replica) {
		pgd_page->replica = NULL;
		smp_wmb();
	}

	
	for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
		pgd_t pgdval = READ_ONCE(pgd[pgd_idx]);
		p4d_t *p4d_base;

		if (pgd_none(pgdval) || !pgd_present(pgdval))
			continue;

		
		if (pgtable_l5_enabled())
			clear_replica_pointer_if_present(pgd_val(pgdval) & PTE_PFN_MASK);

		p4d_base = p4d_offset(&pgd[pgd_idx], 0);
		if (!p4d_base)
			continue;

		
		for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
			p4d_t p4dval = READ_ONCE(p4d_base[p4d_idx]);
			pud_t *pud_base;

			if (p4d_none(p4dval) || !p4d_present(p4dval))
				continue;

			
			clear_replica_pointer_if_present(p4d_val(p4dval) & PTE_PFN_MASK);

			pud_base = pud_offset(&p4d_base[p4d_idx], 0);
			if (!pud_base)
				continue;

			
			for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
				pud_t pudval = READ_ONCE(pud_base[pud_idx]);
				pmd_t *pmd_base;

				if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
					continue;

				
				clear_replica_pointer_if_present(pud_val(pudval) & PTE_PFN_MASK);

				pmd_base = pmd_offset(&pud_base[pud_idx], 0);
				if (!pmd_base)
					continue;

				
				for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
					pmd_t pmdval = READ_ONCE(pmd_base[pmd_idx]);

					if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
						continue;

					
					clear_replica_pointer_if_present(pmd_val(pmdval) & PTE_PFN_MASK);
				}
			}
		}
	}

	smp_wmb();
}

static void free_page_table_page(struct page *page, const char *level_name)
{
	struct ptdesc *pt;

	if (!page)
		return;

	
	if (page->replica) {
		page->replica = NULL;
		smp_wmb();
	}

	
	pt = page_ptdesc(page);
	pagetable_dtor(pt);
	__free_page(page);
}

static void free_all_replica_trees_except(struct mm_struct *mm, int keep_node)
{
	int node;

	for_each_node_mask(node, mm->repl_pgd_nodes) {
		pgd_t *node_pgd;
		struct page *node_pgd_page;
		int pgd_idx, p4d_idx, pud_idx, pmd_idx;

		
		if (node == keep_node)
			continue;

		node_pgd = mm->pgd_replicas[node];
		if (!node_pgd)
			continue;

		node_pgd_page = virt_to_page(node_pgd);

		
		for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
			pgd_t pgdval = READ_ONCE(node_pgd[pgd_idx]);
			p4d_t *p4d_base;
			unsigned long child_phys;
			struct page *child_page;

			if (pgd_none(pgdval) || !pgd_present(pgdval))
				continue;

			
			p4d_base = p4d_offset(&node_pgd[pgd_idx], 0);
			if (!p4d_base || !virt_addr_valid(p4d_base))
				continue;

			
			child_page = NULL;
			if (pgtable_l5_enabled()) {
				child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
				if (child_phys && pfn_valid(child_phys >> PAGE_SHIFT)) {
					child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
					if (page_to_nid(child_page) != node)
						child_page = NULL;
				}
			}

			
			for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
				p4d_t p4dval = READ_ONCE(p4d_base[p4d_idx]);
				pud_t *pud_base;
				unsigned long pud_phys;
				struct page *pud_page;

				if (p4d_none(p4dval) || !p4d_present(p4dval))
					continue;

				
				pud_base = pud_offset(&p4d_base[p4d_idx], 0);
				if (!pud_base || !virt_addr_valid(pud_base))
					continue;

				
				pud_phys = p4d_val(p4dval) & PTE_PFN_MASK;
				pud_page = NULL;
				if (pud_phys && pfn_valid(pud_phys >> PAGE_SHIFT)) {
					pud_page = pfn_to_page(pud_phys >> PAGE_SHIFT);
					if (page_to_nid(pud_page) != node)
						pud_page = NULL;
				}

				
				if (pud_page) {
					
					for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
						pud_t pudval = READ_ONCE(pud_base[pud_idx]);
						pmd_t *pmd_base;
						unsigned long pmd_phys;
						struct page *pmd_page;

						if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
							continue;

						
						pmd_base = pmd_offset(&pud_base[pud_idx], 0);
						if (!pmd_base || !virt_addr_valid(pmd_base))
							continue;

						
						pmd_phys = pud_val(pudval) & PTE_PFN_MASK;
						pmd_page = NULL;
						if (pmd_phys && pfn_valid(pmd_phys >> PAGE_SHIFT)) {
							pmd_page = pfn_to_page(pmd_phys >> PAGE_SHIFT);
							if (page_to_nid(pmd_page) != node)
								pmd_page = NULL;
						}

						
						if (pmd_page) {
							
							for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
								pmd_t pmdval = READ_ONCE(pmd_base[pmd_idx]);
								unsigned long pte_phys;
								struct page *pte_page;

								if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
									continue;

								
								pte_phys = pmd_val(pmdval) & PTE_PFN_MASK;
								if (pte_phys && pfn_valid(pte_phys >> PAGE_SHIFT)) {
									pte_page = pfn_to_page(pte_phys >> PAGE_SHIFT);
									if (pte_page && page_to_nid(pte_page) == node)
										free_page_table_page(pte_page, "pte");
								}
							}
							
							free_page_table_page(pmd_page, "pmd");
						}
					}
					
					free_page_table_page(pud_page, "pud");
				}
			}

			
			if (child_page)
				free_page_table_page(child_page, "p4d");
		}

		
		free_page_table_page(node_pgd_page, "pgd");

		
		mm->pgd_replicas[node] = NULL;
		smp_wmb();
	}

	
	for_each_node_mask(node, mm->repl_pgd_nodes) {
		if (node != keep_node && mm->pgd_replicas[node] != NULL) {
			pr_err("MITOSIS ERROR: free_all_replicas_except - pgd_replicas[%d] not NULL after freeing!\n", node);
			mm->pgd_replicas[node] = NULL;
		}
	}
	smp_wmb();
}

static void switch_cr3_ipi(void *info)
{
    struct cr3_switch_info *switch_info = info;
    struct mm_struct *mm = switch_info->mm;
    
    
    if (current->mm == mm || current->active_mm == mm) {
        unsigned long old_cr3 = read_cr3_pa();
        unsigned long current_pgd_pa = old_cr3 & PAGE_MASK;
        unsigned long original_pgd_pa = __pa(switch_info->original_pgd);
        
        
        if (current_pgd_pa != original_pgd_pa) {
            unsigned long new_cr3 = original_pgd_pa | (old_cr3 & ~PAGE_MASK);
            native_write_cr3(new_cr3);
            __flush_tlb_all();
            
            pr_debug("MITOSIS IPI: CPU %d switched CR3 for mm %px\n",
                     smp_processor_id(), mm);
        }
    }
}

void pgtable_repl_disable(struct mm_struct *mm)
{
    unsigned long flags;
    int original_node;
    bool was_enabled;
    nodemask_t saved_nodes;
    struct cr3_switch_info switch_info;

    if (!mm || mm == &init_mm)
        return;

    mutex_lock(&global_repl_mutex);

    /* Quick check without holding repl_mutex */
    if (!mm->repl_pgd_enabled && nodes_empty(mm->repl_pgd_nodes)) {
        mutex_unlock(&global_repl_mutex);
        return;
    }

    mutex_lock(&mm->repl_mutex);

    was_enabled = mm->repl_pgd_enabled;
    saved_nodes = mm->repl_pgd_nodes;

    /* Validate original_pgd */
    if (!mm->original_pgd) {
        if (mm->pgd) {
            mm->original_pgd = mm->pgd;
        } else {
            mutex_unlock(&mm->repl_mutex);
            mutex_unlock(&global_repl_mutex);
            return;
        }
    }

    if (!virt_addr_valid(mm->original_pgd)) {
        mutex_unlock(&mm->repl_mutex);
        mutex_unlock(&global_repl_mutex);
        return;
    }

    original_node = page_to_nid(virt_to_page(mm->original_pgd));

    /*
     * Phase 1: Disable replication flag
     * This prevents new page table operations from using replicas
     */
    smp_store_release(&mm->repl_pgd_enabled, false);
    smp_wmb();

    /*
     * Phase 2: Switch mm->pgd back to original
     */
    mm->pgd = mm->original_pgd;
    smp_wmb();

    /*
     * Phase 3: Switch all CPUs using this mm to the original PGD
     */
    switch_info.mm = mm;
    switch_info.original_pgd = mm->original_pgd;
    
    local_irq_save(flags);
    if (current->mm == mm || current->active_mm == mm) {
        unsigned long old_cr3 = read_cr3_pa();
        unsigned long new_cr3 = __pa(mm->original_pgd) | (old_cr3 & ~PAGE_MASK);
        write_cr3(new_cr3);
        __flush_tlb_all();
    }
    local_irq_restore(flags);
    
    /* IPI all CPUs in this mm's cpumask */
    on_each_cpu_mask(mm_cpumask(mm), switch_cr3_ipi, &switch_info, 1);
    
    /* Also IPI all other CPUs (for lazy TLB) */
    smp_call_function(switch_cr3_ipi, &switch_info, 1);
    
    /*
     * Phase 4: Synchronize
     * After this, no CPU should be using any replica PGD
     */
    smp_mb();
    synchronize_rcu();
    smp_mb();

    /*
     * Phase 5: Clear replica pointers in the PRIMARY tree
     * This breaks the circular replica chains
     */
    clear_replica_pointers_in_tree(mm);

    /*
     * Phase 6: Free all replica trees
     * Now mm->pgd_replicas[] still contains valid pointers!
     */
    free_all_replica_trees_except(mm, original_node);

    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    smp_wmb();

    /*
     * Phase 8: Final cleanup
     */
    nodes_clear(mm->repl_pgd_nodes);
    mm->original_pgd = NULL;
    smp_wmb();
    
    pr_info("MITOSIS: Disabled page table replication for mm %p\n", mm);

    flush_tlb_all();
    smp_mb();

    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);
    
    synchronize_rcu();
    smp_mb();
}

int pgtable_repl_init_mm(struct mm_struct *mm)
{
	if (!mm) {
		pr_err("MITOSIS: init_mm - NULL mm\n");
		return -EINVAL;
	}

	if (mm->repl_pgd_enabled) {
		pr_warn("MITOSIS: init_mm - already enabled\n");
		return -EALREADY;
	}

	if (!nodes_empty(mm->repl_pgd_nodes)) {
		pr_warn("MITOSIS: init_mm - nodes already set\n");
		nodes_clear(mm->repl_pgd_nodes);
	}

	memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
	return 0;
}

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int mitosis_status_show(struct seq_file *m, void *v)
{
    struct task_struct *p;
    int total = 0, replicated = 0;
    int total_writes, replica_uses, primary_uses;
    int pte_sets, pmd_sets, pud_sets, p4d_sets, pgd_sets;
    int pte_clears, pmd_clears, pud_clears, p4d_clears, pgd_clears;
    int pte_agg, pmd_agg, pud_agg, p4d_agg, pgd_agg;
    int prot_commits, ptep_get_and_clears;

    seq_printf(m, "Mitosis Page Table Replication Status\n");
    seq_printf(m, "======================================\n\n");

    /* CR3 statistics */
    total_writes = atomic_read(&total_cr3_writes);
    replica_uses = atomic_read(&replica_hits);
    primary_uses = atomic_read(&primary_hits);

    seq_printf(m, "CR3 Statistics:\n");
    seq_printf(m, "  CR3 writes: %d\n", total_writes);
    seq_printf(m, "  Replica uses: %d\n", replica_uses);
    seq_printf(m, "  Primary uses: %d\n", primary_uses);

    if (total_writes > 0) {
        int pct = (replica_uses * 100) / total_writes;
        seq_printf(m, "  Replica hit rate: %d%%\n", pct);
    }

    /* Setter statistics */
    pte_sets = atomic_read(&repl_pte_sets);
    pmd_sets = atomic_read(&repl_pmd_sets);
    pud_sets = atomic_read(&repl_pud_sets);
    p4d_sets = atomic_read(&repl_p4d_sets);
    pgd_sets = atomic_read(&repl_pgd_sets);

    seq_printf(m, "\nReplicated Set Operations:\n");
    seq_printf(m, "  PTE sets: %d\n", pte_sets);
    seq_printf(m, "  PMD sets: %d\n", pmd_sets);
    seq_printf(m, "  PUD sets: %d\n", pud_sets);
    seq_printf(m, "  P4D sets: %d\n", p4d_sets);
    seq_printf(m, "  PGD sets: %d\n", pgd_sets);
    seq_printf(m, "  Total replicated sets: %d\n", 
               pte_sets + pmd_sets + pud_sets + p4d_sets + pgd_sets);

    /* Clear statistics */
    pte_clears = atomic_read(&repl_pte_clears);
    pmd_clears = atomic_read(&repl_pmd_clears);
    pud_clears = atomic_read(&repl_pud_clears);
    p4d_clears = atomic_read(&repl_p4d_clears);
    pgd_clears = atomic_read(&repl_pgd_clears);

    seq_printf(m, "\nReplicated Clear Operations:\n");
    seq_printf(m, "  PTE clears: %d\n", pte_clears);
    seq_printf(m, "  PMD clears: %d\n", pmd_clears);
    seq_printf(m, "  PUD clears: %d\n", pud_clears);
    seq_printf(m, "  P4D clears: %d\n", p4d_clears);
    seq_printf(m, "  PGD clears: %d\n", pgd_clears);
    seq_printf(m, "  Total replicated clears: %d\n",
               pte_clears + pmd_clears + pud_clears + p4d_clears + pgd_clears);

    /* Getter aggregation statistics */
    pte_agg = atomic_read(&repl_pte_gets_aggregated);
    pmd_agg = atomic_read(&repl_pmd_gets_aggregated);
    pud_agg = atomic_read(&repl_pud_gets_aggregated);
    p4d_agg = atomic_read(&repl_p4d_gets_aggregated);
    pgd_agg = atomic_read(&repl_pgd_gets_aggregated);

    seq_printf(m, "\nGet Operations with Flag Aggregation:\n");
    seq_printf(m, "  PTE gets (aggregated): %d\n", pte_agg);
    seq_printf(m, "  PMD gets (aggregated): %d\n", pmd_agg);
    seq_printf(m, "  PUD gets (aggregated): %d\n", pud_agg);
    seq_printf(m, "  P4D gets (aggregated): %d\n", p4d_agg);
    seq_printf(m, "  PGD gets (aggregated): %d\n", pgd_agg);
    seq_printf(m, "  Total aggregated gets: %d\n",
               pte_agg + pmd_agg + pud_agg + p4d_agg + pgd_agg);

    /* Special operation statistics */
    prot_commits = atomic_read(&repl_prot_commits);
    ptep_get_and_clears = atomic_read(&repl_ptep_get_and_clears);

    seq_printf(m, "\nSpecial Operations:\n");
    seq_printf(m, "  Prot commits: %d\n", prot_commits);
    seq_printf(m, "  PTEP get and clear: %d\n", ptep_get_and_clears);
    seq_printf(m, "  PTEP get and clear (aggregated): %d\n", atomic_read(&repl_ptep_get_and_clears_aggregated));

    seq_printf(m, "\nProcesses with replication:\n");

    rcu_read_lock();
    for_each_process(p) {
        if (p->mm) {
            total++;
            if (p->mm->repl_pgd_enabled) {
                int node;
                int node_count = 0;

                replicated++;
                seq_printf(m, "  PID %d (%s): nodes=", p->pid, p->comm);
                for_each_node_mask(node, p->mm->repl_pgd_nodes) {
                    seq_printf(m, "%d,", node);
                    node_count++;
                }
                seq_printf(m, " (total: %d nodes)\n", node_count);

                if (nodes_empty(p->mm->repl_pgd_nodes)) {
                    seq_printf(m, "    WARNING: Enabled but no nodes set!\n");
                }

                if (p->mm->pgd) {
                    struct page *pgd_page = virt_to_page(p->mm->pgd);
                    seq_printf(m, "    Primary PGD on node %d\n", page_to_nid(pgd_page));

                    if (pgd_page->replica) {
                        seq_printf(m, "    Has replica chain\n");
                    } else {
                        seq_printf(m, "    WARNING: No replica chain!\n");
                    }
                }    
                
                if (p->repl_forced_node >= 0) {
                    seq_printf(m, "    WASP Forced Node: %d\n", p->repl_forced_node);
                } else {
                    seq_printf(m, "    WASP Mode: Auto (local node)\n");
                }
            }
        }
    }
    rcu_read_unlock();

    seq_printf(m, "\nSummary: %d/%d processes using replication\n", replicated,
           total);

    if (replicated > 0) {
        seq_printf(m, "\nReplication is ACTIVE\n");
    } else {
        seq_printf(m, "\nReplication is INACTIVE\n");
    }

    return 0;
}

static int mitosis_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_status_show, NULL);
}

static const struct proc_ops mitosis_status_ops = {
	.proc_open = mitosis_status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init mitosis_proc_init(void)
{
    proc_create("mitosis_status", 0444, NULL, &mitosis_status_ops);
    return 0;
}
late_initcall(mitosis_proc_init);

#endif

static int __init mitosis_setup(char *str)
{
    sysctl_mitosis_auto_enable = 1;
    return 1;
}
__setup("mitosis", mitosis_setup);

void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[MAX_NUMNODES];
    void *src_addr, *dst_addr;
    int count = 0;
    int i, ret;
    unsigned long flags;

    /* Valid early returns - not errors */
    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!base_page)
        BUG();

    local_irq_save(flags);

    /* Check enabled state with IRQs disabled */
    if (!mm->repl_pgd_enabled) {
        local_irq_restore(flags);
        return;
    }

    /* Already has replicas */
    if (READ_ONCE(base_page->replica)) {
        local_irq_restore(flags);
        return;
    }

    src_addr = page_address(base_page);
    if (!src_addr)
        BUG();

    ret = alloc_pte_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        BUG();

    /* Clear replica pointers before linking */
    for (i = 1; i < count; i++)
        pages[i]->replica = NULL;
    smp_wmb();

    /* Copy content to all replicas */
    for (i = 1; i < count; i++) {
        dst_addr = page_address(pages[i]);
        if (!dst_addr)
            BUG();
        memcpy(dst_addr, src_addr, PAGE_SIZE);
        clflush_cache_range(dst_addr, PAGE_SIZE);
    }
    smp_mb();

    /* Link replicas */
    if (count > 1) {
        if (!link_page_replicas(pages, count))
            BUG();
    }

    smp_mb();
    local_irq_restore(flags);
}

void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[MAX_NUMNODES];
    void *src_addr, *dst_addr;
    int count = 0;
    int i, ret;
    unsigned long flags;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!base_page)
        BUG();

    local_irq_save(flags);

    if (!mm->repl_pgd_enabled) {
        local_irq_restore(flags);
        return;
    }

    if (READ_ONCE(base_page->replica)) {
        local_irq_restore(flags);
        return;
    }

    src_addr = page_address(base_page);
    if (!src_addr)
        BUG();

    ret = alloc_pmd_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        BUG();

    for (i = 1; i < count; i++)
        pages[i]->replica = NULL;
    smp_wmb();

    for (i = 1; i < count; i++) {
        dst_addr = page_address(pages[i]);
        if (!dst_addr)
            BUG();
        memcpy(dst_addr, src_addr, PAGE_SIZE);
        clflush_cache_range(dst_addr, PAGE_SIZE);
    }
    smp_mb();

    if (count > 1) {
        if (!link_page_replicas(pages, count))
            BUG();
    }

    smp_mb();
    local_irq_restore(flags);
}

void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[MAX_NUMNODES];
    void *src_addr, *dst_addr;
    int count = 0;
    int i, ret;
    unsigned long flags;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!base_page)
        BUG();

    local_irq_save(flags);

    if (!mm->repl_pgd_enabled) {
        local_irq_restore(flags);
        return;
    }

    if (READ_ONCE(base_page->replica)) {
        local_irq_restore(flags);
        return;
    }

    src_addr = page_address(base_page);
    if (!src_addr)
        BUG();

    ret = alloc_pud_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        BUG();

    for (i = 1; i < count; i++)
        pages[i]->replica = NULL;
    smp_wmb();

    for (i = 1; i < count; i++) {
        dst_addr = page_address(pages[i]);
        if (!dst_addr)
            BUG();
        memcpy(dst_addr, src_addr, PAGE_SIZE);
        clflush_cache_range(dst_addr, PAGE_SIZE);
    }
    smp_mb();

    if (count > 1) {
        if (!link_page_replicas(pages, count))
            BUG();
    }

    smp_mb();
    local_irq_restore(flags);
}

void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[MAX_NUMNODES];
    void *src_addr, *dst_addr;
    int count = 0;
    int i, ret;
    unsigned long flags;

    if (!pgtable_l5_enabled())
        return;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!base_page)
        BUG();

    local_irq_save(flags);

    if (!mm->repl_pgd_enabled) {
        local_irq_restore(flags);
        return;
    }

    if (READ_ONCE(base_page->replica)) {
        local_irq_restore(flags);
        return;
    }

    src_addr = page_address(base_page);
    if (!src_addr)
        BUG();

    ret = alloc_p4d_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        BUG();

    for (i = 1; i < count; i++)
        pages[i]->replica = NULL;
    smp_wmb();

    for (i = 1; i < count; i++) {
        dst_addr = page_address(pages[i]);
        if (!dst_addr)
            BUG();
        memcpy(dst_addr, src_addr, PAGE_SIZE);
        clflush_cache_range(dst_addr, PAGE_SIZE);
    }
    smp_mb();

    if (count > 1) {
        if (!link_page_replicas(pages, count))
            BUG();
    }

    smp_mb();
    local_irq_restore(flags);
}


void pgtable_repl_release_pte(unsigned long pfn)
{
    struct page *page, *cur_page, *next_page;
    int iterations = 0;
    unsigned long flags;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    if (!page)
        BUG();

    local_irq_save(flags);

    cur_page = xchg(&page->replica, NULL);
    if (!cur_page) {
        local_irq_restore(flags);
        return;
    }

    while (cur_page && cur_page != page) {
        struct ptdesc *pt;

        next_page = cur_page->replica;
        cur_page->replica = NULL;
        smp_wmb();

        pt = page_ptdesc(cur_page);
        pagetable_dtor(pt);
        __free_page(cur_page);

        cur_page = next_page;

        if (++iterations >= MAX_NUMNODES)
            BUG();
    }

    local_irq_restore(flags);
}

void pgtable_repl_release_pmd(unsigned long pfn)
{
    struct page *page, *cur_page, *next_page;
    int iterations = 0;
    unsigned long flags;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    if (!page)
        BUG();

    local_irq_save(flags);

    cur_page = xchg(&page->replica, NULL);
    if (!cur_page) {
        local_irq_restore(flags);
        return;
    }

    while (cur_page && cur_page != page) {
        struct ptdesc *pt;

        next_page = cur_page->replica;
        cur_page->replica = NULL;
        smp_wmb();

        pt = page_ptdesc(cur_page);
        pagetable_dtor(pt);
        __free_page(cur_page);

        cur_page = next_page;

        if (++iterations >= MAX_NUMNODES)
            BUG();
    }

    local_irq_restore(flags);
}

void pgtable_repl_release_pud(unsigned long pfn)
{
    struct page *page, *cur_page, *next_page;
    int iterations = 0;
    unsigned long flags;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    if (!page)
        BUG();

    local_irq_save(flags);

    cur_page = xchg(&page->replica, NULL);
    if (!cur_page) {
        local_irq_restore(flags);
        return;
    }

    while (cur_page && cur_page != page) {
        struct ptdesc *pt;

        next_page = cur_page->replica;
        cur_page->replica = NULL;
        smp_wmb();

        pt = page_ptdesc(cur_page);
        pagetable_dtor(pt);
        __free_page(cur_page);

        cur_page = next_page;

        if (++iterations >= MAX_NUMNODES)
            BUG();
    }

    local_irq_restore(flags);
}

void pgtable_repl_release_p4d(unsigned long pfn)
{
    struct page *page, *cur_page, *next_page;
    int iterations = 0;
    unsigned long flags;

    if (!pgtable_l5_enabled())
        return;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    if (!page)
        BUG();

    local_irq_save(flags);

    cur_page = xchg(&page->replica, NULL);
    if (!cur_page) {
        local_irq_restore(flags);
        return;
    }

    while (cur_page && cur_page != page) {
        struct ptdesc *pt;

        next_page = cur_page->replica;
        cur_page->replica = NULL;
        smp_wmb();

        pt = page_ptdesc(cur_page);
        pagetable_dtor(pt);
        __free_page(cur_page);

        cur_page = next_page;

        if (++iterations >= MAX_NUMNODES)
            BUG();
    }

    local_irq_restore(flags);
}

int mitosis_sysctl_handler(const struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	
	struct ctl_table tmp_table = {
		.data = &sysctl_mitosis_auto_enable,
		.maxlen = sizeof(int),
		.mode = table->mode,
	};

	
	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret < 0)
		return ret;

	
	if (write) {
		
		if (sysctl_mitosis_auto_enable <= 0)
			sysctl_mitosis_auto_enable = -1;
		else
			sysctl_mitosis_auto_enable = 1;

		pr_debug("Mitosis: Auto-enable for new processes set to %s.\n",
			sysctl_mitosis_auto_enable == 1 ? "ENABLED" : "DISABLED");
	}

	return 0;
}

int mitosis_inherit_sysctl_handler(const struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	struct ctl_table tmp_table = {
		.data = &sysctl_mitosis_inherit,
		.maxlen = sizeof(int),
		.mode = table->mode,
	};

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret < 0)
		return ret;

	if (write) {
		if (sysctl_mitosis_inherit <= 0)
			sysctl_mitosis_inherit = -1;
		else
			sysctl_mitosis_inherit = 1;

		pr_debug("Mitosis: Inheritance for child processes set to %s.\n",
			sysctl_mitosis_inherit == 1 ? "ENABLED" : "DISABLED");
	}

	return 0;
}

pte_t pgtable_repl_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep)
{
    struct page *pte_page, *cur_page;
    struct page *repl;
    unsigned long offset;
    int iterations = 0;
    pte_t pte;
    pteval_t flags;
    pteval_t original_flags;

    if (!ptep)
        BUG();

    /* Kernel threads or init_mm - never replicated */
    if (!current || !current->mm || current->mm == &init_mm) {
        return native_ptep_get_and_clear(ptep);
    }

    pte_page = virt_to_page(ptep);
    repl = READ_ONCE(pte_page->replica);

    /* If this page has no replicas, just clear natively */
    if (!repl) {
        return native_ptep_get_and_clear(ptep);
    }

    /* Track replicated ptep_get_and_clear operation */
    atomic_inc(&repl_ptep_get_and_clears);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    flags = 0;
    original_flags = 0;
    pte = __pte(0);

    /* Walk ALL replicas, clear each and aggregate flags */
    cur_page = pte_page;
    do {
        void *page_addr = page_address(cur_page);
        pte_t *replica_pte;
        pte_t replica_val;

        if (!page_addr)
            BUG();

        replica_pte = (pte_t *)(page_addr + offset);
        replica_val = native_ptep_get_and_clear(replica_pte);
        
        /* First iteration: capture the full pte value and original flags */
        if (iterations == 0) {
            pte = replica_val;
            original_flags = pte_flags(replica_val);
        }
        
        flags |= pte_flags(replica_val);

        cur_page = READ_ONCE(cur_page->replica);
        if (++iterations >= MAX_NUMNODES)
            BUG();
    } while (cur_page && cur_page != pte_page);

    /* Track if we actually aggregated different flags */
    if (flags != original_flags)
        atomic_inc(&repl_ptep_get_and_clears_aggregated);

    /* Return pte with aggregated flags from all replicas */
    return pte_set_flags(pte, flags);
}

EXPORT_SYMBOL(pgtable_repl_read_cr3);
EXPORT_SYMBOL(pgtable_repl_write_cr3);
EXPORT_SYMBOL(pgtable_repl_enable);
EXPORT_SYMBOL(pgtable_repl_disable);
EXPORT_SYMBOL(pgtable_repl_set_pte);
EXPORT_SYMBOL(pgtable_repl_set_pmd);
EXPORT_SYMBOL(pgtable_repl_set_pud);
EXPORT_SYMBOL(pgtable_repl_set_p4d);
EXPORT_SYMBOL(pgtable_repl_set_pgd);
EXPORT_SYMBOL(pgtable_repl_clear_pte);
EXPORT_SYMBOL(pgtable_repl_clear_pmd);
EXPORT_SYMBOL(pgtable_repl_clear_pud);
EXPORT_SYMBOL(pgtable_repl_clear_p4d);
EXPORT_SYMBOL(pgtable_repl_clear_pgd);
EXPORT_SYMBOL(pgtable_repl_ptep_modify_prot_commit);
EXPORT_SYMBOL(pgtable_repl_init_mm);
EXPORT_SYMBOL(total_cr3_writes);
EXPORT_SYMBOL(replica_hits);
EXPORT_SYMBOL(primary_hits);
EXPORT_SYMBOL(pgtable_repl_alloc_pte);
EXPORT_SYMBOL(pgtable_repl_alloc_pmd);
EXPORT_SYMBOL(pgtable_repl_alloc_pud);
EXPORT_SYMBOL(pgtable_repl_alloc_p4d);
EXPORT_SYMBOL(pgtable_repl_release_pte);
EXPORT_SYMBOL(pgtable_repl_release_pmd);
EXPORT_SYMBOL(pgtable_repl_release_pud);
EXPORT_SYMBOL(pgtable_repl_release_p4d);
EXPORT_SYMBOL(mitosis_sysctl_handler);
EXPORT_SYMBOL(mitosis_inherit_sysctl_handler);
EXPORT_SYMBOL(pgtable_repl_get_pte);
EXPORT_SYMBOL(pgtable_repl_get_pmd);
EXPORT_SYMBOL(pgtable_repl_get_pud);
EXPORT_SYMBOL(pgtable_repl_get_p4d);
EXPORT_SYMBOL(pgtable_repl_get_pgd);
EXPORT_SYMBOL(pgtable_repl_ptep_get_and_clear);

#endif
