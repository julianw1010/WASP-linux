// arch/x86/include/asm/pgtable_repl.h
#ifndef _ASM_X86_PGTABLE_REPL_H
#define _ASM_X86_PGTABLE_REPL_H

#ifdef CONFIG_PGTABLE_REPLICATION

extern int sysctl_mitosis_auto_enable;
extern int sysctl_mitosis_inherit;

unsigned long pgtable_repl_read_cr3(void);
void pgtable_repl_write_cr3(unsigned long cr3);
void pgtable_repl_cr3_intercept(unsigned long cr3);
int pgtable_repl_init_mm(struct mm_struct *mm);
int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes);
void pgtable_repl_disable(struct mm_struct *mm);
void pgtable_repl_set_pgd(pgd_t *pgd, pgd_t pgdval);
void pgtable_repl_set_p4d(p4d_t *p4d, p4d_t p4dval);
void pgtable_repl_set_pud(pud_t *pud, pud_t pudval);
void pgtable_repl_set_pmd(pmd_t *pmd, pmd_t pmdval);
void pgtable_repl_set_pte(pte_t *pte, pte_t pteval);
pte_t pgtable_repl_get_pte(pte_t *ptep);
pmd_t pgtable_repl_get_pmd(pmd_t *pmdp);
pud_t pgtable_repl_get_pud(pud_t *pudp);
p4d_t pgtable_repl_get_p4d(p4d_t *p4dp);
pgd_t pgtable_repl_get_pgd(pgd_t *pgdp);
bool mitosis_should_auto_enable(void);

void pgtable_repl_clear_pte(pte_t *ptep, struct mm_struct *mm);
void pgtable_repl_clear_pmd(pmd_t *pmdp);
void pgtable_repl_clear_pud(pud_t *pudp);
void pgtable_repl_clear_p4d(p4d_t *p4dp);
void pgtable_repl_clear_pgd(pgd_t *pgdp);

void pgtable_repl_ptep_modify_prot_commit(struct vm_area_struct *vma, 
                                          unsigned long addr,
                                          pte_t *ptep, pte_t pte);
void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long addr);
void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long addr);
void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long addr);
void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long addr);

/* Release operations - called before page table release */
void pgtable_repl_release_pte(unsigned long addr);
void pgtable_repl_release_pmd(unsigned long addr);
void pgtable_repl_release_pud(unsigned long addr);
void pgtable_repl_release_p4d(unsigned long addr);

int mitosis_sysctl_handler(const struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos);
int mitosis_inherit_sysctl_handler(const struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos); 

pte_t pgtable_repl_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep);

#else

/* Stub for when CONFIG_PGTABLE_REPLICATION is disabled */
static inline void verify_live_pagetable_walk(unsigned long address, int expected_node) { }

static inline unsigned long pgtable_repl_read_cr3(void) { return native_read_cr3(); }
static inline void pgtable_repl_write_cr3(unsigned long cr3) { native_write_cr3(cr3); }
static inline int pgtable_repl_init_mm(struct mm_struct *mm) { return 0; }

static inline void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long addr) {}

static inline void pgtable_repl_release_pte(unsigned long addr) {}
static inline void pgtable_repl_release_pmd(unsigned long addr) {}
static inline void pgtable_repl_release_pud(unsigned long addr) {}
static inline void pgtable_repl_release_p4d(unsigned long addr) {}

#endif

#endif /* _ASM_X86_PGTABLE_REPL_H */
