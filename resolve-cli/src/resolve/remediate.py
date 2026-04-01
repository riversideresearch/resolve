import argparse
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def find_symbol_offset(elf: ELFFile, symbol_name: str) -> int | None:
    """
    Locate the virtual address of a symbol inside an ELF file.
    """
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol.name == symbol_name:
                    return int(symbol["st_value"])
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


def patch_symbol(
    elf_path: Path,
    symbol_name: str,
    new_bytes: bytes
):
    """
    Patch the value of a symbol inside an ELF binary

    Raises ValueError if the symbol is not found
    """
    with elf_path.open("rb") as f:
        elf = ELFFile(f)
        symbol_addr = find_symbol_offset(elf, symbol_name)

        if symbol_addr is None:
            raise ValueError(f"Symbol '{symbol_name}' not found in ELF")

        file_offset = find_file_offset(elf, symbol_addr)
        if file_offset is None:
            raise ValueError(
                f"Symbol '{symbol_name}' not located in any PT_LOAD segment"
            )

    # Read and patch the binary
    data = bytearray(elf_path.read_bytes())
    print(f"{len(new_bytes)}")

    print(f"patching {data[file_offset:file_offset + len(new_bytes)]} with {new_bytes}")
    data[file_offset:file_offset + len(new_bytes)] = new_bytes

    data[file_offset:file_offset + len(new_bytes)] = new_bytes

    # Write patched output
    elf_path.write_bytes(data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target_bin",
        type=Path,
    )
    args = parser.parse_args()

    patch_symbol(args.target_bin, "should_run", 0xFFFF_0001.to_bytes(4, "little"))

if __name__ == "__main__":
    main()