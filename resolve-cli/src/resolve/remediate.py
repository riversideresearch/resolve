import argparse
import mmap
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

CWE_PATCHES = {
    0: [0, 1, 2, 3, 4, 5, 6],
    121: [0],
    122: [0],
    123: [0],
    125: [0],
    131: [0],
    369: [3]
}

def find_symbol_offset(elf: ELFFile, symbol_name: str):
    """
    Locate the symbol inside an ELF file via symbol table lookup.
    """
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol.name == symbol_name:
                    return symbol
    return None


def find_file_offset(elf: ELFFile, vaddr: int) -> int | None:
    """
    Convert a virtual address to a file offset by scanning PT_LOAD segments.
    """
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD":
            start = int(segment["p_vaddr"])
            end = start + int(segment["p_memsz"])
            if start <= vaddr < end:
                return int(segment["p_offset"] + (vaddr - start))
    return None


def set_byte(mm: mmap.mmap, offset: int, bit: int):
    """
    Set byte @ offset
    """
    # Get the original bit at the byte offset
    original = mm[offset]
    print(f"[DEBUGGING] Original bit: {original}")

    if original == bit:
        print(f"[INFO] set_bit and original bit match: {bit} no changes made to binary")
        return original, bit

    modified = bit
    mm[offset] = modified

    return original, modified

def patch_symbol(elf_path: Path, symbol_name: str, cwe: int, bit: int):
    """
    Patch the value of a symbol inside the ELF binary
    """
    with elf_path.open("r+b") as f, mmap.mmap(f.fileno(), 0) as mm:
        elf = ELFFile(mm)

        symbol = find_symbol_offset(elf, symbol_name)
        if symbol is None:
            raise ValueError(f"[ERROR] Symbol '{symbol_name}' not found")

        symbol_addr = int(symbol["st_value"])
        symbol_size = int(symbol["st_size"])

        base_offset = find_file_offset(elf, symbol_addr)
        if base_offset is None:
            raise ValueError(
                f"Symbol '{symbol_name}' not located in any PT_LOAD segment"
            )

        if cwe not in CWE_PATCHES:
            raise ValueError(f"[ERROR] Unsupported CWE {cwe}")

        offsets = CWE_PATCHES[cwe]

        for rel_offset in offsets:
            if rel_offset < 0 or rel_offset >= symbol_size:
                raise ValueError(
                    f"[ERROR] Offset {rel_offset} out of bounds "
                    f"(symbol size = {symbol_size})"
                )

            target_offset = base_offset + rel_offset

            if target_offset >= mm.size():
                raise ValueError(f"[ERROR] Target offset {target_offset:#x} out of range")
            
            original, modified = set_byte(mm, target_offset, bit)
            print(
                f"[INFO] Patched {symbol_name}[{rel_offset}] "
                f"@ file offset {target_offset:#x}: {original:#x} -> {modified:#x}"
        )

        mm.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target_bin",
        type=Path,
    )

    parser.add_argument(
        "symbol",
        type=str,
    )

    parser.add_argument(
        "cwe",
        type=int,
    )

    parser.add_argument(
        "bit",
        type=int,
    )

    args = parser.parse_args()
    patch_symbol(args.target_bin, args.symbol, args.cwe, args.bit)

if __name__ == "__main__":
    main()
