import argparse
import mmap
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

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

def patch_symbol(elf_path: Path, symbol_name: str, index: int):
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

        if index < 0 or index >= symbol_size:
            raise ValueError(
                f"[ERROR] Index '{index}' out of bounds (size={symbol_size})"
            )

        base_offset = find_file_offset(elf, symbol_addr)
        if base_offset is None:
            raise ValueError(
                f"Symbol '{symbol_name}' not located in any PT_LOAD segment"
            )
        
        target_offset = base_offset + index
        if target_offset >= mm.size():
            raise ValueError("[ERROR] Target offset exceeds file size")

        mm[target_offset] = 0 if mm[target_offset] != 0 else 1
        mm.flush()

        print(
            f"[INFO] Patched {symbol_name}[{index}] "
            f"@ file offset {target_offset:#x}"
        )



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
        "index",
        type=int,
    )

    args = parser.parse_args()
    patch_symbol(args.target_bin, args.symbol, args.index)

if __name__ == "__main__":
    main()