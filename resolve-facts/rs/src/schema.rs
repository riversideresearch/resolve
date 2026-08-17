// notes:
// - some fields are over-sized to pad the struct to alignment

use std::mem::*;

pub const FORMAT_VERSION: u32 = 1;

// Node identifier: index in its parent modules Node array
pub type NodeID = u32;

// Offset into modules interned string pool
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Interned(pub u32);

#[allow(dead_code)] // cbindgen
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeType {
    Module = 0,
    Function = 1,
    Argument = 2,
    BasicBlock = 3,
    Instruction = 4,
    GlobalVariable = 5,
}

#[allow(dead_code)] // cbindgen
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linkage {
    Other = 0,
    ExternalLinkage = 1,
}

#[allow(dead_code)] // cbindgen
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallType {
    Direct = 0,
    Indirect = 1,
}

// positions in Node.meta indicating which properties are present.
pub const P_IDX: u32 = 1 << 0;
pub const P_NAME: u32 = 1 << 1;
pub const P_OPCODE: u32 = 1 << 2;
pub const P_LINKAGE: u32 = 1 << 3;
pub const P_CALL_TYPE: u32 = 1 << 4;
pub const P_SOURCE_LOC: u32 = 1 << 5;
pub const P_SOURCE_FILE: u32 = 1 << 6;
pub const P_FUNCTION_TYPE: u32 = 1 << 7;
pub const P_ADDRESS_TAKEN: u32 = 1 << 8;

#[allow(dead_code)] // cbindgen
pub const PRESENT_MASK: u32 = u16::MAX as u32;
pub const NODE_TYPE_SHIFT: u32 = 16;
#[allow(dead_code)] // cbindgen
pub const NODE_TYPE_MASK: u32 = 0xff << NODE_TYPE_SHIFT;
pub const LINKAGE_SHIFT: u32 = 24;
pub const LINKAGE_MASK: u32 = 0x0f << LINKAGE_SHIFT;
pub const CALL_TYPE_SHIFT: u32 = 28;
pub const CALL_TYPE_MASK: u32 = 0x0f << CALL_TYPE_SHIFT;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub meta: u32,
    pub idx: u32,
    pub name: Interned,
    pub opcode: Interned,
    pub source_line: u32,
    pub source_col: u32,
    pub source_file: Interned,
    pub function_type: Interned,
}

#[allow(dead_code)] // reader
impl Node {
    pub const fn new(ty: NodeType) -> Self {
        Self {
            meta: (ty as u32) << NODE_TYPE_SHIFT,
            idx: 0,
            name: Interned(0),
            opcode: Interned(0),
            source_line: 0,
            source_col: 0,
            source_file: Interned(0),
            function_type: Interned(0),
        }
    }

    pub const fn present(&self) -> u16 {
        (self.meta & PRESENT_MASK) as u16
    }

    pub const fn has(&self, property: u32) -> bool {
        self.meta & property != 0
    }

    pub const fn node_type_raw(&self) -> u8 {
        ((self.meta & NODE_TYPE_MASK) >> NODE_TYPE_SHIFT) as u8
    }

    pub const fn linkage_raw(&self) -> Option<u8> {
        if self.has(P_LINKAGE) {
            Some(((self.meta & LINKAGE_MASK) >> LINKAGE_SHIFT) as u8)
        } else {
            None
        }
    }

    pub const fn call_type_raw(&self) -> Option<u8> {
        if self.has(P_CALL_TYPE) {
            Some(((self.meta & CALL_TYPE_MASK) >> CALL_TYPE_SHIFT) as u8)
        } else {
            None
        }
    }

    pub fn set_present(&mut self, property: u32) {
        self.meta |= property;
    }

    pub fn set_linkage(&mut self, linkage: Linkage) {
        self.meta = (self.meta & !LINKAGE_MASK) | ((linkage as u32) << LINKAGE_SHIFT) | P_LINKAGE;
    }

    pub fn set_call_type(&mut self, call_type: CallType) {
        self.meta =
            (self.meta & !CALL_TYPE_MASK) | ((call_type as u32) << CALL_TYPE_SHIFT) | P_CALL_TYPE;
    }
}

#[allow(dead_code)] // cbindgen
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    Calls = 0,
    Contains = 1,
    DataFlowTo = 2,
    References = 3,
    EntryPoint = 4,
    ControlFlowTo = 5,
}

// A unique (src, dst) pair within a module. Edge arrays are sorted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Edge {
    pub src: NodeID,
    pub dst: NodeID,
    pub kinds: u32,
}

#[allow(dead_code)] // reader
impl Edge {
    pub const fn has_kind(&self, kind: EdgeKind) -> bool {
        self.kinds & (1 << kind as u8) != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModuleHeader {
    pub version: u32,
    pub node_count: u32,
    pub edge_count: u32,
    pub string_pool_len: u32,
}

#[allow(dead_code)] // reader
impl ModuleHeader {
    pub fn byte_len(&self) -> Option<usize> {
        let nodes = usize::try_from(self.node_count)
            .ok()?
            .checked_mul(size_of::<Node>())?;
        let edges = usize::try_from(self.edge_count)
            .ok()?
            .checked_mul(size_of::<Edge>())?;
        let strings = usize::try_from(self.string_pool_len).ok()?;

        size_of::<Self>()
            .checked_add(nodes)?
            .checked_add(edges)?
            .checked_add(strings)
    }
}

// "View" API:

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // reader
pub struct ModuleRef<'a> {
    bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // reader
pub enum ViewError {
    Misaligned,
    Truncated,
    UnsupportedVersion,
    UnalignedModuleLength,
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Misaligned => f.write_str("facts bytes are not 4-byte aligned"),
            Self::Truncated => f.write_str("facts module is truncated or has an invalid length"),
            Self::UnsupportedVersion => f.write_str("facts module has an unsupported version"),
            Self::UnalignedModuleLength => {
                f.write_str("facts module length is not a multiple of 4 bytes")
            }
        }
    }
}

impl std::error::Error for ViewError {}

#[allow(dead_code)] // reader
impl<'a> ModuleRef<'a> {
    // Borrows the first complete module in "bytes" and returns the unconsumed suffix
    pub fn from_prefix(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ViewError> {
        if bytes.len() < size_of::<ModuleHeader>() {
            return Err(ViewError::Truncated);
        }
        if bytes.as_ptr().align_offset(align_of::<ModuleHeader>()) != 0 {
            return Err(ViewError::Misaligned);
        }

        let header = unsafe { &*bytes.as_ptr().cast::<ModuleHeader>() };
        if header.version != FORMAT_VERSION {
            return Err(ViewError::UnsupportedVersion);
        }

        let module_len = header.byte_len().ok_or(ViewError::Truncated)?;
        if module_len % align_of::<ModuleHeader>() != 0 {
            return Err(ViewError::UnalignedModuleLength);
        }
        if bytes.len() < module_len {
            return Err(ViewError::Truncated);
        }

        let (module, rest) = bytes.split_at(module_len);
        Ok((Self { bytes: module }, rest))
    }

    pub fn header(&self) -> &'a ModuleHeader {
        unsafe { &*self.bytes.as_ptr().cast::<ModuleHeader>() }
    }

    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn nodes(&self) -> &'a [Node] {
        let header = self.header();
        let data = unsafe { self.bytes.as_ptr().add(size_of::<ModuleHeader>()) };

        unsafe { std::slice::from_raw_parts(data.cast::<Node>(), header.node_count as usize) }
    }

    pub fn edges(&self) -> &'a [Edge] {
        let header = self.header();
        let nodes_len = header.node_count as usize * size_of::<Node>();
        let data = unsafe {
            self.bytes
                .as_ptr()
                .add(size_of::<ModuleHeader>() + nodes_len)
        };

        unsafe { std::slice::from_raw_parts(data.cast::<Edge>(), header.edge_count as usize) }
    }

    pub fn string_pool(&self) -> &'a [u8] {
        let header = self.header();
        let nodes_len = header.node_count as usize * size_of::<Node>();
        let edges_len = header.edge_count as usize * size_of::<Edge>();
        let start = size_of::<ModuleHeader>() + nodes_len + edges_len;
        &self.bytes[start..start + header.string_pool_len as usize]
    }

    // Resolves an interned ID without allocating or copying the string bytes.
    pub fn string_bytes(&self, id: Interned) -> Option<&'a [u8]> {
        let pool = self.string_pool();
        let offset = usize::try_from(id.0).ok()?;
        let length_end = offset.checked_add(size_of::<u32>())?;
        let length_bytes: [u8; 4] = pool.get(offset..length_end)?.try_into().ok()?;
        let length = u32::from_le_bytes(length_bytes) as usize;
        let value_end = length_end.checked_add(length)?;
        pool.get(length_end..value_end)
    }

    pub fn string(&self, id: Interned) -> Option<&'a str> {
        std::str::from_utf8(self.string_bytes(id)?).ok()
    }

    pub fn node(&self, id: NodeID) -> Option<&'a Node> {
        self.nodes().get(id as usize)
    }
}

// A non-owning view over a complete concatenation of modules
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // reader
pub struct FactsRef<'a> {
    bytes: &'a [u8],
}

#[allow(dead_code)] // reader
impl<'a> FactsRef<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub const fn modules(self) -> ModuleIter<'a> {
        ModuleIter {
            remaining: self.bytes,
        }
    }

    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[allow(dead_code)] // reader
pub struct ModuleIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for ModuleIter<'a> {
    type Item = Result<ModuleRef<'a>, ViewError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        match ModuleRef::from_prefix(self.remaining) {
            Ok((module, rest)) => {
                self.remaining = rest;
                Some(Ok(module))
            }
            Err(error) => {
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

/// cbindgen:ignore
#[allow(dead_code)] // cbindgen
const LAYOUT_ASSERTIONS: () = {
    assert!(size_of::<Interned>() == 4);
    assert!(align_of::<Interned>() == 4);
    assert!(size_of::<ModuleHeader>() == 16);
    assert!(align_of::<ModuleHeader>() == 4);
    assert!(size_of::<Node>() == 32);
    assert!(align_of::<Node>() == 4);
    assert!(size_of::<Edge>() == 12);
    assert!(align_of::<Edge>() == 4);
};
