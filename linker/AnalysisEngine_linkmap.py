#!/usr/bin/env python3
#
# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for licensing information.

import argparse
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import TextIO
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

from extract_facts import embed_facts, extract_facts

# ------------------------------------------------------------------------------
# Global counters and settings
# ------------------------------------------------------------------------------
next_node_id = 1
next_edge_id = 1
#globalID = "linkmap"  # used for generating node/edge globalIDs
globalID = os.getenv("GlobalContext", "") + "linkmap"

# Dictionaries for already-created nodes
sections     = {}   # key: section name
object_files = {}   # key: file path
symbols      = {}   # key: symbol name
loads        = {}   # key: load path
mem_configs  = {}   # key: memconfig name

# Output file handles (set in main)
node_file = None
edge_file = None
node_prop_file = None
edge_prop_file = None

# Lists to store event nodes for optional linking later
merge_events   = []  # Each entry: (merge_node_id, file1, file2)
archive_events = []  # Each entry: (archive_node_id, archive, ref, symbol)

# ------------------------------------------------------------------------------
# Helper functions for generating global IDs
# ------------------------------------------------------------------------------
def node_global_local(localID):
    """Produces a node identifier string like 'linkmap:node_5'."""
    return f"{globalID}:node_{localID}"

def edge_global_local(localID):
    """Produces an edge identifier string like 'linkmap:edge_5'."""
    return f"{globalID}:edge_{localID}"


# ------------------------------------------------------------------------------
# Base creation functions (for default nodes)
# ------------------------------------------------------------------------------
def get_or_create_section(section_name, vma, lma, size, align):
    global next_node_id
    if section_name not in sections:
        node_id = next_node_id
        next_node_id += 1
        sections[section_name] = node_id
        gnode = node_global_local(node_id)
        node_file.write(f"{gnode},section\n")
        node_prop_file.write(f"{gnode},name,{section_name}\n")
        node_prop_file.write(f"{gnode},VMA,{vma}\n")
        node_prop_file.write(f"{gnode},LMA,{lma}\n")
        node_prop_file.write(f"{gnode},Size,{size}\n")
        node_prop_file.write(f"{gnode},Align,{align}\n")
    return sections[section_name]

def get_or_create_object_file(obj_name):
    global next_node_id
    if obj_name not in object_files:
        node_id = next_node_id
        next_node_id += 1
        object_files[obj_name] = node_id
        gnode = node_global_local(node_id)
        node_file.write(f"{gnode},objectFile\n")
        node_prop_file.write(f"{gnode},path,{obj_name}\n")
    return object_files[obj_name]

def get_or_create_symbol(symbol_name):
    global next_node_id
    if symbol_name not in symbols:
        node_id = next_node_id
        next_node_id += 1
        symbols[symbol_name] = node_id
        gnode = node_global_local(node_id)
        node_file.write(f"{gnode},symbol\n")
        node_prop_file.write(f"{gnode},name,{symbol_name}\n")
    return symbols[symbol_name]

def create_edge(source_id, edge_type, target_id, vma, lma, size, align):
    global next_edge_id
    eid = next_edge_id
    next_edge_id += 1
    gedge = edge_global_local(eid)
    sFQN = node_global_local(source_id)
    tFQN = node_global_local(target_id)
    edge_file.write(f"{gedge},{edge_type},{sFQN},{tFQN}\n")
    edge_prop_file.write(f"{gedge},VMA,{vma}\n")
    edge_prop_file.write(f"{gedge},LMA,{lma}\n")
    edge_prop_file.write(f"{gedge},Size,{size}\n")
    edge_prop_file.write(f"{gedge},Align,{align}\n")

# ------------------------------------------------------------------------------
# Extra node creation functions (for extra states)
# ------------------------------------------------------------------------------
def get_or_create_load(load_path):
    global next_node_id
    if load_path not in loads:
        node_id = next_node_id
        next_node_id += 1
        loads[load_path] = node_id
        gnode = node_global_local(node_id)
        node_file.write(f"{gnode},load\n")
        node_prop_file.write(f"{gnode},path,{load_path}\n")
    return loads[load_path]

def get_or_create_memconfig(mem_name, origin, length, attributes):
    global next_node_id
    key = mem_name  # we might combine with origin?
    if key not in mem_configs:
        node_id = next_node_id
        next_node_id += 1
        mem_configs[key] = node_id
        gnode = node_global_local(node_id)
        node_file.write(f"{gnode},memoryRegion\n")
        node_prop_file.write(f"{gnode},name,{mem_name}\n")
        node_prop_file.write(f"{gnode},origin,{origin}\n")
        node_prop_file.write(f"{gnode},length,{length}\n")
        node_prop_file.write(f"{gnode},attributes,{attributes if attributes is not None else ''}\n")
    return mem_configs[key]

def create_merge_event(prop_code, file1, value1, file2, value2):
    global next_node_id
    node_id = next_node_id
    next_node_id += 1
    gnode = node_global_local(node_id)
    node_file.write(f"{gnode},mergeEvent\n")
    node_prop_file.write(f"{gnode},propertyCode,{prop_code}\n")
    node_prop_file.write(f"{gnode},file1,{file1}\n")
    node_prop_file.write(f"{gnode},value1,{value1}\n")
    node_prop_file.write(f"{gnode},file2,{file2}\n")
    node_prop_file.write(f"{gnode},value2,{value2}\n")
    return node_id

def create_archive_event(archive, ref, symbol):
    global next_node_id
    node_id = next_node_id
    next_node_id += 1
    gnode = node_global_local(node_id)
    node_file.write(f"{gnode},archiveEvent\n")
    node_prop_file.write(f"{gnode},archive,{archive}\n")
    node_prop_file.write(f"{gnode},reference,{ref}\n")
    node_prop_file.write(f"{gnode},symbol,{symbol}\n")
    return node_id

def create_discarded_section(section_name, vma, size, file_path):
    global next_node_id
    node_id = next_node_id
    next_node_id += 1
    gnode = node_global_local(node_id)
    node_file.write(f"{gnode},discardedSection\n")
    node_prop_file.write(f"{gnode},name,{section_name}\n")
    node_prop_file.write(f"{gnode},VMA,{vma}\n")
    node_prop_file.write(f"{gnode},Size,{size}\n")
    node_prop_file.write(f"{gnode},file,{file_path}\n")
    return node_id

# ------------------------------------------------------------------------------
# Regular expressions for matching various lines - Old version with better documentation, need to extend to all regex used in Updated version
# ------------------------------------------------------------------------------
# Regex #1: 4 numeric columns + remainder. Example shape:
#     0x0000000000002a8  0x0000000000002a8  0x1c  4  .interp   <internal>:(.interp)
# MAP_4COL_RE = re.compile(
#     r'^\s*'
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(1): VMA
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(2): LMA
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(3): Size
#     r'(\d+)\s+'                 # group(4): Align (decimal)
#     r'(.*)$'                    # group(5): the remainder
# )

# # Regex #2: One numeric column + a symbol name. Example:
# #     0x0000000000005370     cJSON_IsInvalid
# MAP_ADDR_SYM_RE = re.compile(
#     r'^\s*'
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(1): address (VMA)
#     r'(\S+)'
#     r'\s*$'
# )

# # Regex #3: Section + address + size + something (like object file). Example:
# #     .text  0x0000000000007b25   0x0  /usr/bin/.../crtendS.o
# # Here we do NOT have LMA or Align in the line. So we capture only VMA, Size, and “the rest”.
# MAP_SECTION_ADDR_SIZE_RE = re.compile(
#     r'^\s*'
#     r'(\.\S+)\s+'               # group(1): section name (starts with '.')
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(2): VMA
#     r'(?:0x)?([0-9A-Fa-f]+)\s+'  # group(3): Size
#     r'(.*)$'                    # group(4): remainder (maybe object file)
# )

# ------------------------------------------------------------------------------
# Regular expressions for matching various lines - Updated
# ------------------------------------------------------------------------------
MAP_4COL_RE = re.compile(
    r'^\s*(?:0x)?([0-9A-Fa-f]+)\s+(?:0x)?([0-9A-Fa-f]+)\s+(?:0x)?([0-9A-Fa-f]+)\s+(\d+)\s+(.*)$'
)
MAP_ADDR_SYM_RE = re.compile(
    r'^\s*(?:0x)?([0-9A-Fa-f]+)\s+(\S+)\s*$'
)
MAP_SECTION_ADDR_SIZE_RE = re.compile(
    r'^\s*(\.\S+)\s+(?:0x)?([0-9A-Fa-f]+)\s+(?:0x)?([0-9A-Fa-f]+)\s+(.*)$'
)
MAP_LOAD_RE = re.compile(r'^\s*LOAD\s+(\S+)\s*$')
MAP_MEMCONFIG_RE = re.compile(
    r'^\s*(\S+)\s+(0x[0-9A-Fa-f]+)\s+((?:0x)?[0-9A-Fa-f]+|\d+)(?:\s+(\S+))?\s*$'
)
MERGE_PROP_RE = re.compile(
    r'^Removed property (\S+) to merge (\S+)\s+\(([^)]+)\)\s+and\s+(\S+)\s+\(([^)]+)\)'
)
ARCHIVE_MEMBER_RE = re.compile(
    r'^(?P<archive>\S+)\s+(?P<ref>\S+)\s+\((?P<symbol>[^)]+)\)$'
)
DISCARDED_DETAIL_RE = re.compile(
    r'^\s*(?:0x)?([0-9A-Fa-f]+)\s+(?:0x)?([0-9A-Fa-f]+)\s+(.*)$'
)

# ------------------------------------------------------------------------------
# Default parsing function (for section/objectFile/symbol lines)
# ------------------------------------------------------------------------------
def parse_line(line):
    """
    Tries three strategies:
      1) Four numeric columns + remainder.
      2) One address + symbol.
      3) Section name + address + size + remainder.
    Returns a tuple: (vma, lma, size, align, out_section, in_object, symbol_name)
    Any element may be None if not present.
    """
    line = line.strip()
    if not line:
        return None
    m = MAP_4COL_RE.match(line)
    if m:
        vma, lma, size, align, remainder = m.groups()
        tokens = remainder.split(None, 2)
        out_sec = None
        in_obj = None
        sym = None
        def looks_like_in_object(s):
            return (":" in s) and ("(" in s) and (")" in s)
        for t in tokens:
            if t.startswith("."):
                out_sec = t
            elif looks_like_in_object(t):
                in_obj = t
            else:
                sym = t
        return (vma, lma, size, align, out_sec, in_obj, sym)
    m = MAP_ADDR_SYM_RE.match(line)
    if m:
        vma, symbol = m.groups()
        return (vma, None, None, None, None, None, symbol)
    m = MAP_SECTION_ADDR_SIZE_RE.match(line)
    if m:
        out_sec, vma, size, remainder = m.groups()
        lma = None
        align = None
        tokens = remainder.split(None, 1)
        in_obj = tokens[0] if tokens else None
        return (vma, lma, size, align, out_sec, in_obj, None)
    return None

# ------------------------------------------------------------------------------
# Two-Pass Processing Functions
# ------------------------------------------------------------------------------
def process_default(map_file: TextIO):
    """
    First pass: Process default lines (sections, objectFiles, symbols)
    and create default nodes and edges.
    """
    current_section_id = None
    current_object_id = None
    for line in map_file:
        # Skip extra header lines so that we process only default lines.
        if any(header in line for header in [
                "Memory Configuration",
                "Linker script and memory map",
                "Discarded input sections",
                "Merging program properties",
                "Archive member included to satisfy reference"
            ]):
            continue
        parsed = parse_line(line)
        if not parsed:
            continue
        (vma, lma, size, align, out_sec, in_obj, sym) = parsed
        if out_sec is not None:
            current_section_id = get_or_create_section(out_sec, vma, lma, size, align)
            current_object_id = None
        if in_obj is not None and current_section_id is not None:
            obj_name = in_obj.split(":", 1)[0].strip()
            current_object_id = get_or_create_object_file(obj_name)
            create_edge(current_section_id, "contains", current_object_id, vma, lma, size, align)
        if sym is not None and current_object_id is not None:
            sym_id = get_or_create_symbol(sym.strip())
            create_edge(current_object_id, "defines", sym_id, vma, lma, size, align)

def process_extra(map_file: TextIO):
    """
    Second pass: Process extra states (load, memory config, merge events,
    archive events, and discarded sections).
    """
    current_discarded_section_name = None
    for line in map_file:
        sline = line.strip()
        if not sline:
            continue
        # Process LOAD commands.
        m = MAP_LOAD_RE.match(line)
        if m:
            load_path = m.group(1)
            get_or_create_load(load_path)
        # Process memory configuration.
        m = MAP_MEMCONFIG_RE.match(line)
        if m:
            mem_name, origin, length, attributes = m.groups()
            get_or_create_memconfig(mem_name, origin, length, attributes)
        # Process merging properties.
        m = MERGE_PROP_RE.match(line)
        if m:
            prop_code, file1, value1, file2, value2 = m.groups()
            merge_node_id = create_merge_event(prop_code, file1, value1, file2, value2)
            merge_events.append((merge_node_id, file1, file2))
        # Process archive member events.
        m = ARCHIVE_MEMBER_RE.match(line)
        if m:
            archive = m.group("archive")
            ref = m.group("ref")
            symbol = m.group("symbol")
            archive_node_id = create_archive_event(archive, ref, symbol)
            archive_events.append((archive_node_id, archive, ref, symbol))
        # Process discarded sections.
        if sline.startswith("."):
            current_discarded_section_name = sline.split()[0]
        else:
            m = DISCARDED_DETAIL_RE.match(line)
            if m and current_discarded_section_name is not None:
                vma_val, size_val, file_path = m.groups()
                create_discarded_section(current_discarded_section_name, vma_val, size_val, file_path)
                current_discarded_section_name = None

def write_definitions(out_dir: Path):
    definitions = {
      "context": f"{globalID}",
      "description": "This file defines the node and edge types, as well as their properties, produced by the link map analysis engine.",
      "node_types": {
          "section": "A section from the linker map (e.g., .text, .rodata).",
          "objectFile": "An object or archive file included during linking.",
          "symbol": "A symbol defined in an object file.",
          "load": "A file explicitly loaded via the linker script.",
          "memoryRegion": "A memory region defined in the memory configuration.",
          "mergeEvent": "An event representing a property merge between files.",
          "archiveEvent": "An event representing an archive member used to satisfy a reference.",
          "discardedSection": "A section that was discarded during linking."
      },
      "edge_types": {
          "contains": "Edge from a section node to an objectFile node indicating inclusion.",
          "defines": "Edge from an objectFile node to a symbol node indicating definition.",
          "merged": "Edge linking an objectFile node to a merge event.",
          "archiveRef": "Edge linking an objectFile node to an archive event."
      },
      "node_properties": {
          "name": "The name of the node (e.g., section name or symbol name).",
          "VMA": "Virtual Memory Address.",
          "LMA": "Load Memory Address (if applicable).",
          "Size": "The size of the section, symbol, etc.",
          "Align": "The alignment value.",
          "path": "File path for objectFile or load nodes.",
          "origin": "Origin address for a memory region.",
          "length": "Length of the memory region.",
          "attributes": "Attributes of the memory region.",
          "propertyCode": "Property code in a merge event.",
          "file1": "The first file involved in a merge event.",
          "value1": "The value from the first file in a merge event.",
          "file2": "The second file involved in a merge event.",
          "value2": "The value from the second file in a merge event.",
          "archive": "Archive file in an archive event.",
          "reference": "Referencing file in an archive event."
      },
      "edge_properties": {
          "VMA": "Virtual Memory Address associated with the edge.",
          "LMA": "Load Memory Address associated with the edge.",
          "Size": "Size associated with the edge.",
          "Align": "Alignment associated with the edge."
      }
    }
    with (out_dir / "definitions.json").open("w") as def_file:
        json.dump(definitions, def_file, indent=2)

def write_rules(out_dir: Path):
    # The derived predicates below enrich the base facts with domain-specific logic.
    rules = r'''
.decl nodes(fqn:symbol, type:symbol)
.decl nodeprops(fqn:symbol, key:symbol, val:symbol)
.decl edges(fqn:symbol, type:symbol, src:symbol, tgt:symbol)
.decl edgeprops(fqn:symbol, key:symbol, val:symbol)

.input nodes(filename="build_linkmap_nodes.facts", delimiter=",", headers=true)
.input edges(filename="build_linkmap_edges.facts", delimiter=",", headers=true)
.input nodeprops(filename="build_linkmap_nodeprops.facts", delimiter=",", headers=true)
.input edgeprops(filename="build_linkmap_edgeprops.facts", delimiter=",", headers=true)
.input nodes(filename="build_linkmap_inferred_nodes.facts", delimiter=",", headers=true)
.input edges(filename="build_linkmap_inferred_edges.facts", delimiter=",", headers=true)
.input nodeprops(filename="build_linkmap_inferred_nodeprops.facts", delimiter=",", headers=true)
.input edgeprops(filename="build_linkmap_inferred_edgeprops.facts", delimiter=",", headers=true)

.decl inferredNodes(fqn:symbol, type:symbol)
.decl inferredEdges(fqn:symbol, type:symbol, src:symbol, tgt:symbol)
.decl inferredNodeProps(fqn:symbol, key:symbol, val:symbol)
.decl inferredEdgeProps(fqn:symbol, key:symbol, val:symbol)

.output inferredNodes(headers=true, delimiter=",", filename="/shared-volume/ProgramAnalysis/build/linkmap/inferred/nodes.facts")
.output inferredEdges(headers=true, delimiter=",", filename="/shared-volume/ProgramAnalysis/build/linkmap/inferred/edges.facts")
.output inferredNodeProps(headers=true, delimiter=",", filename="/shared-volume/ProgramAnalysis/build/linkmap/inferred/nodeprops.facts")
.output inferredEdgeProps(headers=true, delimiter=",", filename="/shared-volume/ProgramAnalysis/build/linkmap/inferred/edgeprops.facts")

///////////////////////////////////////////////////////////////////////////////
// Create an edge loadFqn -> objFqn if both have the same path
///////////////////////////////////////////////////////////////////////////////
inferredEdges(
    cat("load->objectFile->", loadFqn, "->", objFqn), // Edge FQN
    "load2objectFile",                                // Edge type
    loadFqn,                                          // src
    objFqn                                            // tgt
) :-
    nodes(loadFqn, "load"),
    nodeprops(loadFqn, "path", P),
    nodes(objFqn, "objectFile"),
    nodeprops(objFqn, "path", P).

///////////////////////////////////////////////////////////////////////////////
// Attach an 'inferredBy' property to that new edge
///////////////////////////////////////////////////////////////////////////////
inferredEdgeProps(
    cat("load->objectFile->", loadFqn, "->", objFqn),
    "inferredBy",
    "rule_loadObjectFileSamePath"
) :-
    nodes(loadFqn, "load"),
    nodeprops(loadFqn, "path", P),
    nodes(objFqn, "objectFile"),
    nodeprops(objFqn, "path", P).

///////////////////////////////////////////////////////////////////////////////
// (A) Insert an edge from memoryRegion -> discardedSection if same 'name'
///////////////////////////////////////////////////////////////////////////////
inferredEdges(
    cat("memRegion->discardedSection->", memFqn, "->", discFqn),
    "memRegion2discardedSection",
    memFqn,
    discFqn
) :-
    nodes(memFqn, "memoryRegion"),
    nodeprops(memFqn, "name", N),
    nodes(discFqn, "discardedSection"),
    nodeprops(discFqn, "name", N).

///////////////////////////////////////////////////////////////////////////////
// (B) Attach an 'inferredBy' property to that new edge
///////////////////////////////////////////////////////////////////////////////
inferredEdgeProps(
    cat("memRegion->discardedSection->", memFqn, "->", discFqn),
    "inferredBy",
    "rule_memRegionDiscardedSectionSameName"
) :-
    nodes(memFqn, "memoryRegion"),
    nodeprops(memFqn, "name", N),
    nodes(discFqn, "discardedSection"),
    nodeprops(discFqn, "name", N).


////////////////////////////////////////////////////////////////////////////////
// 3 Edge memoryRegion -> section if they share the same name
////////////////////////////////////////////////////////////////////////////////
inferredEdges(
    cat("memRegion->section->", memFqn, "->", secFqn),
    "memRegion2section",
    memFqn,
    secFqn
) :-
    nodes(memFqn, "memoryRegion"),
    nodeprops(memFqn, "name", N),
    nodes(secFqn, "section"),
    nodeprops(secFqn, "name", N).

inferredEdgeProps(
    cat("memRegion->section->", memFqn, "->", secFqn),
    "inferredBy",
    "rule_memRegionSectionSameName"
) :-
    nodes(memFqn, "memoryRegion"),
    nodeprops(memFqn, "name", N),
    nodes(secFqn, "section"),
    nodeprops(secFqn, "name", N).
'''
    with (out_dir / "rules.dl").open("w") as rules_file:
        rules_file.write(rules)

# ------------------------------------------------------------------------------
# Main function: Two-Pass + Post-Processing
# ------------------------------------------------------------------------------
def derive_facts(out_dir: Path, map_file: Path):
    global node_file, edge_file, node_prop_file, edge_prop_file
    node_file = (out_dir / "nodes.facts").open("w")
    edge_file = (out_dir / "edges.facts").open("w")
    node_prop_file = (out_dir / "nodeprops.facts").open("w")
    edge_prop_file = (out_dir / "edgeprops.facts").open("w")

    with map_file.open() as map_f:
        # First pass: default facts.
        process_default(map_f)
        # Second pass: extra facts.
        process_extra(map_f)
    
    # Post-processing: Link merge/archive events with objectFiles.
    for merge_node_id, file1, file2 in merge_events:
        if file1 in object_files:
            create_edge(object_files[file1], "merged", merge_node_id, "", "", "", "")
        if file2 in object_files:
            create_edge(object_files[file2], "merged", merge_node_id, "", "", "", "")
    for archive_node_id, archive, ref, symbol in archive_events:
        if archive in object_files:
            create_edge(object_files[archive], "archiveRef", archive_node_id, "", "", "", "")
        if ref in object_files:
            create_edge(object_files[ref], "archiveRef", archive_node_id, "", "", "", "")
    # Close fact files.
    node_file.close()
    edge_file.close()
    node_prop_file.close()
    edge_prop_file.close()

    write_definitions(out_dir)
    write_rules(out_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Link map and output directory manager.")
    parser.add_argument('--in_map', type=Path, help="Path to the link map file to derive facts")
    parser.add_argument('--in_bin', type=Path, help="Path to the input bin to extract from")
    parser.add_argument('--out_dir', type=Path, help="Path to the output directory")
    parser.add_argument('--out_bin', type=Path, help="File to embed the output into")

    args = parser.parse_args()

    if not args.in_map and not args.in_bin:
        parser.error("You must provide either an input map or an input binary to extract facts from.")

    if not args.out_dir and not args.out_bin:
        parser.error("You must provide either a directory or binary out output facts to.")

    def ingest_facts(out_dir: Path):
        if args.in_map:
            print(f"Using link map at {args.in_map}")
            derive_facts(out_dir, args.in_map)
        else:
            print(f"Using input bin at {args.in_bin}")
            extract_facts(out_dir, args.in_bin)

    def export_facts(out_dir: Path):
        if args.out_bin:
            print(f"Embedding output into {args.out_bin}")
            embed_facts(out_dir, args.out_bin)
    
    if args.out_dir:
        print(f"Using out dir of {args.out_dir}")
        ingest_facts(args.out_dir)
        export_facts(args.out_dir)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            ingest_facts(Path(tmp))
            export_facts(Path(tmp))
