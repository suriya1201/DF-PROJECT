# hide_process.py
import sys
import pyvmi
from memory import PageTableEntry, PteFlag # Import from your memory.py file

# --- Configuration ---
VM_NAME = "your-vm-name"  # The name of your VM in virt-manager/virsh
TARGET_PROCESS_NAME = b"innocent"
# The physical page we will redirect to. Choose an address you know is safe,
# like the kernel's zero page. We can find this with VMI.
CLEAN_PHYSICAL_PAGE = 0x0 

def find_target_process(vmi):
    """Find the target process by name."""
    tasks = vmi.get_process_list()
    for task in tasks:
        if task.name == TARGET_PROCESS_NAME:
            print(f"[+] Found target process '{TARGET_PROCESS_NAME.decode()}' with PID: {task.pid}")
            return task
    return None

def find_code_page_pte(vmi, process, target_va):
    """Find the physical address of the PTE for a given virtual address."""
    # A page table walk is required to find the PTE for a VA.
    # The last level of the walk gives us the PTE's physical address.
    # LibVMI provides a helper for this.
    pte_pa = vmi.translate_virtual_to_physical(target_va, process.pid, pte=True)
    if pte_pa:
        print(f"[+] Found PTE for VA 0x{target_va:x} at PA 0x{pte_pa:x}")
        return pte_pa
    return None

def main():
    # Initialize LibVMI
    try:
        vmi = pyvmi.init(VM_NAME, "kvm")
        print(f"[+] Successfully connected to VM: {VM_NAME}")
    except Exception as e:
        print(f"[-] Failed to initialize LibVMI for VM '{VM_NAME}'. Error: {e}")
        print("    Ensure the VM is running and you have the correct permissions.")
        sys.exit(1)

    # 1. Find the target process
    target_proc = find_target_process(vmi)
    if not target_proc:
        print(f"[-] Could not find process '{TARGET_PROCESS_NAME.decode()}' in the guest.")
        sys.exit(1)

    # 2. Get the target virtual address from the user
    #    (from the output of the 'innocent' program)
    try:
        target_va_str = input("Enter the virtual address of 'secret_function' from the guest: ")
        target_va = int(target_va_str, 16)
    except ValueError:
        print("[-] Invalid address format. Please use hex (e.g., 0x555...).")
        sys.exit(1)

    # 3. Find the PTE for the target code page
    pte_pa = find_code_page_pte(vmi, target_proc, target_va)
    if not pte_pa:
        print(f"[-] Could not find PTE for VA 0x{target_va:x}. Is the address correct?")
        sys.exit(1)

    # 4. Read the original PTE value
    original_pte_value = vmi.read_64(pte_pa)
    original_pte = PageTableEntry(value=original_pte_value)
    print("\n--- Original PTE State ---")
    print(f"VA 0x{target_va:016x} -> PA 0x{original_pte.frame_address:016x} FLAGS {original_pte.flags!s}")

    # 5. Craft the "hidden" PTE using logic from memory.py
    #    We will remap it to a clean page and mark it as non-executable.
    if CLEAN_PHYSICAL_PAGE == 0x0:
        # A good "clean" page is the kernel's zero page. Let's find it.
        CLEAN_PHYSICAL_PAGE = vmi.get_kernel_zero_page_address()
        print(f"[+] Using kernel zero page at PA 0x{CLEAN_PHYSICAL_PAGE:x} for hiding.")

    hidden_pte = original_pte.with_frame_address(
        CLEAN_PHYSICAL_PAGE
    ).with_flags(
        set_flags=PteFlag.EXECUTE_DISABLE
    )
    
    print("\n--- New 'Hidden' PTE State ---")
    print(f"VA 0x{target_va:016x} -> PA 0x{hidden_pte.frame_address:016x} FLAGS {hidden_pte.flags!s}")

    # 6. Write the hidden PTE into the guest's memory
    print(f"\n[*] Writing hidden PTE value 0x{hidden_pte.value:x} to PA 0x{pte_pa:x}...")
    vmi.write_64(pte_pa, hidden_pte.value)
    print("[*] PTE modified.")

    # 7. Flush the TLB for the target address to ensure the change takes effect
    vmi.flush_tlb_vaddr(target_va, target_proc.pid)
    print("[+] TLB flushed for the target page. The code is now hidden.")
    print("\n    You can verify this by trying to attach a debugger (like GDB) to the process")
    print("    inside the VM and examining the memory at the secret_function address.")
    print("    It will either show all zeros or cause a segmentation fault.")

    # --- Restore original state ---
    input("\nPress Enter to restore the original PTE and unhide the code...")
    vmi.write_64(pte_pa, original_pte.value)
    vmi.flush_tlb_vaddr(target_va, target_proc.pid)
    print("[+] Original PTE restored and TLB flushed. The code is visible again.")

    vmi.destroy()

if __name__ == "__main__":
    main()
