"""
User-space helpers for Page Table Entry (PTE) manipulation and memory attribute
remapping (MAS) workflows.

These utilities do not attempt to drive hardware MMUs directly; instead they let
you parse raw PTE values from a dump, tweak permission/cache bits, and produce a
remapped view that can be pushed back into a hypervisor, emulator, or further
analysis pipeline.

The implementation focuses on x86/x86_64 style 64-bit PTEs, but the abstractions
are intentionally small so you can adapt the bit masks for other formats (ARM,
PowerPC MAS registers, etc.) by changing the constants or extending the
dataclasses.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from enum import Enum, IntFlag
from typing import Dict, Iterable, Iterator, Mapping, MutableMapping, Tuple


class PteFlag(IntFlag):
    """Bit positions for common x86/x86_64 page table flags."""

    PRESENT = 1 << 0
    WRITE = 1 << 1
    USER = 1 << 2
    WRITE_THROUGH = 1 << 3
    CACHE_DISABLE = 1 << 4
    ACCESSED = 1 << 5
    DIRTY = 1 << 6
    PAT = 1 << 7  # For levels above PT, this becomes the large-page selector.
    GLOBAL = 1 << 8
    EXECUTE_DISABLE = 1 << 63


# Masks describing how the physical frame number and attribute bits are encoded.
PHYSICAL_FRAME_MASK = 0x000F_FFFF_FFFF_F000
ATTRIBUTE_MASK = PteFlag.WRITE_THROUGH | PteFlag.CACHE_DISABLE | PteFlag.PAT


class MemoryAttribute(Enum):
    """High level memory attribute encodings."""

    WRITE_BACK = "wb"
    WRITE_THROUGH = "wt"
    UNCACHED = "uc"
    UNCACHED_MINUS = "uc-"
    WRITE_COMBINE = "wc"


# PAT/PCD/PWT layout for 4 KiB pages.
DEFAULT_PAT_ENCODING: Mapping[MemoryAttribute, PteFlag] = {
    MemoryAttribute.WRITE_BACK: PteFlag(0),
    MemoryAttribute.WRITE_THROUGH: PteFlag.WRITE_THROUGH,
    MemoryAttribute.UNCACHED: PteFlag.WRITE_THROUGH | PteFlag.CACHE_DISABLE,
    MemoryAttribute.UNCACHED_MINUS: PteFlag.CACHE_DISABLE,
    MemoryAttribute.WRITE_COMBINE: PteFlag.PAT | PteFlag.WRITE_THROUGH,
}


@dataclass(frozen=True, slots=True)
class PageTableEntry:
    """Immutable representation of a single 64-bit PTE."""

    value: int
    page_size: int = 4096

    @property
    def frame_address(self) -> int:
        """Return the physical frame base address."""
        return self.value & PHYSICAL_FRAME_MASK

    def with_frame_address(self, frame_address: int) -> PageTableEntry:
        """Return a copy with the frame address replaced."""
        aligned = frame_address & PHYSICAL_FRAME_MASK
        new_value = (self.value & ~PHYSICAL_FRAME_MASK) | aligned
        return replace(self, value=new_value)

    @property
    def flags(self) -> PteFlag:
        """Return the currently active flag bits."""
        flag_bits = self.value & ~PHYSICAL_FRAME_MASK
        return PteFlag(flag_bits)

    def has(self, flag: PteFlag) -> bool:
        """Check whether a given flag is set."""
        return bool(self.value & flag)

    def with_flags(
        self,
        *,
        set_flags: PteFlag = PteFlag(0),
        clear_flags: PteFlag = PteFlag(0),
    ) -> PageTableEntry:
        """Return a copy with specific flags toggled."""
        value = (self.value | set_flags) & ~clear_flags
        return replace(self, value=value)

    @property
    def attribute_bits(self) -> PteFlag:
        """Return the subset of bits that control cache policy."""
        return PteFlag(self.value & ATTRIBUTE_MASK)

    def with_attribute_bits(self, attribute_bits: PteFlag) -> PageTableEntry:
        """Return a copy with cache attribute bits replaced."""
        masked_bits = attribute_bits & ATTRIBUTE_MASK
        new_value = (self.value & ~int(ATTRIBUTE_MASK)) | int(masked_bits)
        return replace(self, value=new_value)


@dataclass(slots=True)
class PageTable:
    """A sparse view of a page table keyed by virtual address."""

    entries: MutableMapping[int, PageTableEntry]
    level: str = "PT"

    def iter_entries(self) -> Iterator[Tuple[int, PageTableEntry]]:
        """Yield virtual address to entry pairs."""
        return iter(self.entries.items())

    def copy(self) -> PageTable:
        """Return a shallow copy of the table."""
        return PageTable(dict(self.entries), level=self.level)

    def update(self, virtual_address: int, entry: PageTableEntry) -> None:
        """In-place update of a virtual address to a new entry."""
        self.entries[virtual_address] = entry


@dataclass(frozen=True, slots=True)
class MASRule:
    """Describe an address range that should adopt a new memory attribute."""

    start: int
    end: int
    attribute: MemoryAttribute

    def matches(self, virtual_address: int) -> bool:
        return self.start <= virtual_address < self.end


def parse_little_endian_pt(
    raw_pte_bytes: bytes,
    *,
    base_virtual_address: int = 0,
    page_size: int = 4096,
) -> PageTable:
    """
    Parse a contiguous block of little-endian 64-bit PTEs into a PageTable.

    The number of PTEs is inferred from the length of `raw_pte_bytes`.
    """
    if len(raw_pte_bytes) % 8 != 0:
        raise ValueError("Raw PTE buffer length must be a multiple of 8 bytes")

    entries: Dict[int, PageTableEntry] = {}
    for index in range(0, len(raw_pte_bytes), 8):
        value = struct.unpack_from("<Q", raw_pte_bytes, index)[0]
        virtual_address = base_virtual_address + (index // 8) * page_size
        entries[virtual_address] = PageTableEntry(value=value, page_size=page_size)
    return PageTable(entries)


def bulk_update_flags(
    table: PageTable,
    predicate: Mapping[int, bool] | None = None,
    *,
    set_flags: PteFlag = PteFlag(0),
    clear_flags: PteFlag = PteFlag(0),
) -> PageTable:
    """
    Create a new PageTable with flags toggled according to the predicate.

    `predicate` should map virtual addresses to booleans (True means update).
    If no predicate is provided all entries are updated.
    """
    updated = table.copy()
    for virtual_address, entry in list(updated.iter_entries()):
        if predicate is not None and not predicate.get(virtual_address, False):
            continue
        updated.entries[virtual_address] = entry.with_flags(
            set_flags=set_flags, clear_flags=clear_flags
        )
    return updated


def apply_mas_remap(
    table: PageTable,
    rules: Iterable[MASRule],
    *,
    attribute_encoding: Mapping[MemoryAttribute, PteFlag] = DEFAULT_PAT_ENCODING,
) -> PageTable:
    """
    Return a new PageTable with cache attribute bits rewritten via MAS rules.

    Each rule is evaluated in order; the first match wins. Addresses that do
    not match any rule retain their original attribute bits.
    """
    updated = table.copy()
    ordered_rules = tuple(rules)

    for virtual_address, entry in list(updated.iter_entries()):
        for rule in ordered_rules:
            if rule.matches(virtual_address):
                attribute_bits = attribute_encoding[rule.attribute]
                updated.entries[virtual_address] = entry.with_attribute_bits(
                    attribute_bits
                )
                break
    return updated


def dump_table(table: PageTable) -> Iterator[str]:
    """
    Yield human-readable strings for each entry, useful when scripting tooling
    around the analyser.
    """
    for virtual_address, entry in sorted(table.iter_entries()):
        flags = entry.flags
        yield (
            f"VA 0x{virtual_address:016x} -> "
            f"PA 0x{entry.frame_address:016x} "
            f"FLAGS {flags!s}"
        )


class MemoryImage:
    """
    Represents a physical memory image with optional MAS-style remapping.

    You provide a file path containing raw physical memory (or a file-like
    object). If the physical addresses in the guest do not match file offsets
    (for example the dump contains only a window), supply `mappings` where
    each mapping is a tuple (phys_start, file_offset, length).
    """

    def __init__(self, path: str, mappings: Iterable[Tuple[int, int, int]] | None = None):
        self.path = path
        # Sorted list of (phys_start, file_offset, length)
        self._mappings = [] if mappings is None else list(mappings)

    def add_mapping(self, phys_start: int, file_offset: int, length: int) -> None:
        self._mappings.append((phys_start, file_offset, length))

    def _find_mapping(self, phys_addr: int) -> Tuple[int, int, int] | None:
        for phys_start, file_offset, length in self._mappings:
            if phys_start <= phys_addr < phys_start + length:
                return phys_start, file_offset, length
        return None

    def read_physical(self, phys_addr: int, size: int) -> bytes:
        """Read `size` bytes from the physical address space as provided by mappings.

        If no mapping matches the requested address, we assume the file is a
        full physical dump where file offset == physical address.
        """
        mapping = self._find_mapping(phys_addr)
        if mapping is None:
            file_offset = phys_addr
        else:
            phys_start, file_offset_base, _ = mapping
            file_offset = file_offset_base + (phys_addr - phys_start)

        with open(self.path, "rb") as f:
            f.seek(file_offset)
            return f.read(size)


def walk_page_table_x86_64(virtual_address: int, cr3: int, mem: MemoryImage) -> int | None:
    """
    Very small x86_64 page-table walker.

    - `cr3` is the physical base of the PML4 (CR3 value, aligned to 4 KiB)
    - `mem` is a MemoryImage instance used to read physical memory

    Returns the translated physical address or None if the mapping isn't present.
    This implements the standard 4-level walk and recognizes 1 GiB and 2 MiB large
    pages via the PAT/PS bit encoded in our PteFlag.PAT constant.
    """
    # helpers to extract indexes
    def idx(va: int, shift: int) -> int:
        return (va >> shift) & 0x1FF

    pml4_idx = idx(virtual_address, 39)
    pdpt_idx = idx(virtual_address, 30)
    pd_idx = idx(virtual_address, 21)
    pt_idx = idx(virtual_address, 12)
    page_offset = virtual_address & 0xFFF

    # Read PML4E
    pml4e_pa = cr3 + (pml4_idx * 8)
    raw = mem.read_physical(pml4e_pa, 8)
    pml4e = struct.unpack_from("<Q", raw, 0)[0]
    pml4e_entry = PageTableEntry(value=pml4e)
    if not pml4e_entry.has(PteFlag.PRESENT):
        return None

    # PDPT
    pdpt_base = pml4e_entry.frame_address
    pdpte_pa = pdpt_base + (pdpt_idx * 8)
    raw = mem.read_physical(pdpte_pa, 8)
    pdpte = struct.unpack_from("<Q", raw, 0)[0]
    pdpte_entry = PageTableEntry(value=pdpte)
    if not pdpte_entry.has(PteFlag.PRESENT):
        return None

    # 1 GiB large page
    if pdpte_entry.has(PteFlag.PAT):
        phys_base = pdpte_entry.frame_address
        # lower 30 bits are offset inside 1 GiB page
        offset = virtual_address & ((1 << 30) - 1)
        return phys_base + offset

    # PD
    pd_base = pdpte_entry.frame_address
    pde_pa = pd_base + (pd_idx * 8)
    raw = mem.read_physical(pde_pa, 8)
    pde = struct.unpack_from("<Q", raw, 0)[0]
    pde_entry = PageTableEntry(value=pde)
    if not pde_entry.has(PteFlag.PRESENT):
        return None

    # 2 MiB large page
    if pde_entry.has(PteFlag.PAT):
        phys_base = pde_entry.frame_address
        offset = virtual_address & ((1 << 21) - 1)
        return phys_base + offset

    # PT
    pt_base = pde_entry.frame_address
    pte_pa = pt_base + (pt_idx * 8)
    raw = mem.read_physical(pte_pa, 8)
    pte = struct.unpack_from("<Q", raw, 0)[0]
    pte_entry = PageTableEntry(value=pte)
    if not pte_entry.has(PteFlag.PRESENT):
        return None

    phys_base = pte_entry.frame_address
    return phys_base + page_offset


def example_usage() -> None:
    """
    Demonstration of rootkit-like behavior using PTE and MAS manipulation.
    """
    # --- Setup: Define memory layout and initial page table ---

    # Let's define some addresses for our scenario.
    TARGET_VIRTUAL_ADDRESS = 0x4000_1000
    CLEAN_PHYSICAL_PAGE = 0x8001_0000  # Physical page with legitimate code
    MALICIOUS_PHYSICAL_PAGE = 0x9002_0000  # Physical page with rootkit code

    # Create a Page Table Entry (PTE) for a target virtual address.
    # Initially, it points to the "clean" physical page.
    # Flags: Present, User, Writable, Executable (XD=0).
    initial_pte_value = (
        CLEAN_PHYSICAL_PAGE | PteFlag.PRESENT | PteFlag.USER | PteFlag.WRITE
    )
    initial_pte = PageTableEntry(value=initial_pte_value)

    # Create a page table with this single entry.
    table = PageTable(entries={TARGET_VIRTUAL_ADDRESS: initial_pte})

    print("--- Initial 'Normal' Memory View ---")
    print("The page table initially maps the target VA to the clean page.")
    for line in dump_table(table):
        print(line)
    print("-" * 20)

    # --- Hiding Technique 1: PTE Manipulation for Stealth ---
    # A forensics tool scans memory. The rootkit hides by marking its page
    # as non-executable and changing its cache attributes to look like data.

    print("\n--- Rootkit Hiding (Scanner Active) ---")
    print("A scanner is detected. Rootkit modifies PTE to hide.")

    # 1. Apply MAS remapping to change memory type to Write-Combine (often used for device memory).
    # This can evade detectors that look for code in standard Write-Back memory.
    rules = [
        MASRule(
            TARGET_VIRTUAL_ADDRESS,
            TARGET_VIRTUAL_ADDRESS + 0x1000,
            MemoryAttribute.WRITE_COMBINE,
        )
    ]
    hidden_table = apply_mas_remap(table, rules)

    # 2. Use bulk_update_flags to mark the page as non-executable (Execute Disable).
    predicate = {TARGET_VIRTUAL_ADDRESS: True}
    hidden_table = bulk_update_flags(
        hidden_table,
        predicate,
        set_flags=PteFlag.EXECUTE_DISABLE,
    )

    print("PTE is now non-executable and has a different memory attribute.")
    for line in dump_table(hidden_table):
        print(line)
    print("-" * 20)

    # --- Hiding Technique 2: Remapping to Malicious Code ---
    # The rootkit needs to execute. It remaps the virtual address to its
    # own physical code page and ensures it's executable.

    print("\n--- Rootkit Activation (Execution) ---")
    print("Rootkit remaps the VA to its own code and makes it executable.")

    # Get the original PTE from the "normal" view table.
    entry_to_modify = table.entries[TARGET_VIRTUAL_ADDRESS]

    # Create the rootkit's view by remapping the frame address and ensuring it's executable.
    rootkit_view_entry = entry_to_modify.with_frame_address(
        MALICIOUS_PHYSICAL_PAGE
    ).with_flags(clear_flags=PteFlag.EXECUTE_DISABLE)

    rootkit_table = table.copy()
    rootkit_table.update(TARGET_VIRTUAL_ADDRESS, rootkit_view_entry)

    print("PTE now points to malicious code and is executable.")
    for line in dump_table(rootkit_table):
        print(line)
    print("-" * 20)


if __name__ == "__main__":
    example_usage()
