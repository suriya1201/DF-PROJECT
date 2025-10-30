#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>      // Required for find_task_by_vpid
#include <linux/mm.h>         // Required for mm_struct and page table walk
#include <linux/pid.h>        // Required for find_vpid
#include <asm/pgtable.h>      // Required for PTE manipulation functions
#include <asm/tlbflush.h>     // Required for flush_tlb_mm_range

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gemini Code Assist");
MODULE_DESCRIPTION("A module to hide a code page using PTE manipulation.");

// --- Parameters for the module ---
static int target_pid = -1;
module_param(target_pid, int, 0);
MODULE_PARM_DESC(target_pid, "The PID of the process to target");

static unsigned long target_va = 0;
module_param(target_va, ulong, 0);
MODULE_PARM_DESC(target_va, "The virtual address of the code to hide (in hex)");

// --- Globals to store original state for restoration ---
static pte_t *target_ptep = NULL; // Pointer to the Page Table Entry
static pte_t original_pte;
static struct mm_struct *target_mm = NULL;

/**
 * @brief Finds the PTE for a given virtual address in a process's memory space.
 *
 * @param mm The memory descriptor for the process.
 * @param addr The virtual address to look up.
 * @return A pointer to the pte_t, or NULL on failure.
 */
static pte_t *find_pte(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    // pte_offset_map locks the page table. We must call pte_unmap_unlock later.
    return pte_offset_map(pmd, addr);
}

static int __init hider_init(void)
{
    struct task_struct *task;
    pte_t new_pte;
    unsigned long original_phys_addr;
    unsigned long clean_phys_page = 0; // We'll use the kernel zero page

    printk(KERN_INFO "Hider LKM: Initializing...\n");

    if (target_pid == -1 || target_va == 0) {
        printk(KERN_ERR "Hider LKM: Missing parameters 'target_pid' or 'target_va'.\n");
        return -EINVAL;
    }

    // 1. Find the target process's task_struct
    task = get_pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "Hider LKM: Could not find task for PID %d\n", target_pid);
        return -ESRCH;
    }
    target_mm = task->mm;
    printk(KERN_INFO "Hider LKM: Found target process '%s' (PID: %d)\n", task->comm, target_pid);

    // 2. Find the PTE for the target virtual address
    target_ptep = find_pte(target_mm, target_va);
    if (!target_ptep) {
        printk(KERN_ERR "Hider LKM: Could not find PTE for VA 0x%lx\n", target_va);
        return -EFAULT;
    }

    // 3. Save the original PTE value for restoration
    original_pte = *target_ptep;
    original_phys_addr = pte_pfn(original_pte) << PAGE_SHIFT;
    printk(KERN_INFO "Hider LKM: Original PTE found for VA 0x%lx -> PA 0x%lx\n", target_va, original_phys_addr);

    // 4. Craft the "hidden" PTE
    // This translates the logic from your memory.py:
    // .with_frame_address(CLEAN_PHYSICAL_PAGE) -> pfn_pte(clean_pfn, ...)
    // .with_flags(set_flags=PteFlag.EXECUTE_DISABLE) -> pte_mknexec()

    // Get the Page Frame Number (PFN) of the kernel's zero page for our "clean" page
    clean_phys_page = virt_to_phys(empty_zero_page);
    
    // Create a new PTE pointing to the zero page, keeping original permissions but removing execute.
    new_pte = pfn_pte(clean_phys_page >> PAGE_SHIFT, pte_pgprot(original_pte));
    new_pte = pte_mknexec(new_pte); // Set the No-Execute (NX) bit

    printk(KERN_INFO "Hider LKM: Hiding page. New PTE will point to PA 0x%lx (zero page)\n", clean_phys_page);

    // 5. Overwrite the PTE and flush the TLB
    set_pte_at(target_mm, target_va, target_ptep, new_pte);
    flush_tlb_mm_range(target_mm, target_va, target_va + PAGE_SIZE, false);

    pte_unmap_unlock(target_ptep, pmd_off(pud_off(p4d_off(pgd_off(target_mm, target_va), target_va), target_va), target_va)); // Cleanup lock from pte_offset_map

    printk(KERN_INFO "Hider LKM: Page at VA 0x%lx is now hidden.\n", target_va);

    return 0; // Success
}

static void __exit hider_exit(void)
{
    printk(KERN_INFO "Hider LKM: Exiting and restoring original PTE...\n");

    if (target_ptep && target_mm) {
        // Restore the original PTE and flush the TLB
        set_pte_at(target_mm, target_va, target_ptep, original_pte);
        flush_tlb_mm_range(target_mm, target_va, target_va + PAGE_SIZE, false);
        pte_unmap_unlock(target_ptep, pmd_off(pud_off(p4d_off(pgd_off(target_mm, target_va), target_va), target_va), target_va));
        printk(KERN_INFO "Hider LKM: Original PTE for VA 0x%lx has been restored.\n", target_va);
    }
}

module_init(hider_init);
module_exit(hider_exit);