use std::collections::HashMap;

use crate::model::*;

const VERSION: u8 = 0;

// A frame is self-delimiting so multiple `.facts` contributions can be
// concatenated by the linker and decoded one after another.
const FRAME_LEN_OFFSET: usize = 1;
const INTERN_POOL_OFFSET: usize = 5;
const MODULE_COUNT_OFFSET: usize = 9;
const HEADER_LEN: usize = 13;

pub struct FactsBuf(Vec<u8>);

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_len(b: *const FactsBuf) -> usize {
    unsafe { b.as_ref() }.map_or(0, |buf| buf.0.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_data(b: *const FactsBuf) -> *const u8 {
    unsafe { b.as_ref() }.map_or(std::ptr::null(), |buf| buf.0.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_free(b: *mut FactsBuf) {
    if !b.is_null() {
        unsafe {
            drop(Box::from_raw(b));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_serialize(b: *const ProgramFacts) -> *mut FactsBuf {
    let Some(b) = (unsafe { b.as_ref() }) else {
        return std::ptr::null_mut();
    };

    Box::into_raw(Box::new(FactsBuf(b.serialize())))
}

#[derive(Default)]
pub struct Interner {
    ids: HashMap<String, u32>,
    strings: Vec<String>,
}

impl Interner {
    pub fn intern(&mut self, value: &str) -> u32 {
        if let Some(&id) = self.ids.get(value) {
            return id;
        }

        let id = u32::try_from(self.strings.len()).expect("too many interned strings");
        self.strings.push(value.to_owned());
        self.ids.insert(value.to_owned(), id);
        id
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // u32: number of strings
        buf.extend_from_slice(
            &u32::try_from(self.strings.len())
                .expect("TOO MANY STRINGS")
                .to_le_bytes(),
        );

        for text in &self.strings {
            let bytes = text.as_bytes();
            buf.extend_from_slice(
                &u32::try_from(bytes.len())
                    .expect("STRING IS WAY TOO BIG")
                    .to_le_bytes(),
            );
            buf.extend_from_slice(bytes);
        }

        buf
    }
}

impl ProgramFacts {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        let mut i = Interner::default();

        // 0 - version
        buf.push(VERSION);

        // 1..5 - total frame length (patched after the intern pool is added)
        // 5..9 - intern pool offset (patched before the intern pool is added)
        // 9..13 - module count
        buf.resize(HEADER_LEN, 0);
        buf[MODULE_COUNT_OFFSET..HEADER_LEN].copy_from_slice(
            &u32::try_from(self.modules.len())
                .expect("too many modules")
                .to_le_bytes(),
        );

        // sort modules (stability)
        let mut modules: Vec<_> = self.modules.iter().collect();
        modules.sort_unstable_by_key(|(module_id, _)| *module_id);

        for (k, v) in modules {
            // u32: module ID
            buf.extend_from_slice(&k.to_le_bytes());

            // This modules facts
            buf.extend_from_slice(&v.serialize(&mut i));
        }

        let pool_start = u32::try_from(buf.len()).expect("facts frame exceeds 4 GiB");
        buf[INTERN_POOL_OFFSET..MODULE_COUNT_OFFSET].copy_from_slice(&pool_start.to_le_bytes());

        buf.extend_from_slice(&i.as_bytes());

        let frame_len = u32::try_from(buf.len()).expect("facts frame exceeds 4 GiB");
        buf[FRAME_LEN_OFFSET..INTERN_POOL_OFFSET].copy_from_slice(&frame_len.to_le_bytes());

        buf
    }
}

impl ModuleFacts {
    pub fn serialize(&self, i: &mut Interner) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // u32: num nodes
        buf.extend_from_slice(
            &u32::try_from(self.nodes.len())
                .expect("too many nodes")
                .to_le_bytes(),
        );

        // NODES:

        // sort nodes (stability)
        let mut nodes: Vec<_> = self.nodes.iter().collect();
        nodes.sort_unstable_by_key(|(node_id, _)| *node_id);

        for (k, v) in nodes {
            // nodeID: u32
            buf.extend_from_slice(&k.to_le_bytes());

            // NODE
            buf.extend_from_slice(&v.serialize(i));
        }

        // u32: num edges
        buf.extend_from_slice(
            &u32::try_from(self.edges.len())
                .expect("too many edges")
                .to_le_bytes(),
        );

        // EDGES:

        // sort edges (stability)
        let mut edges: Vec<_> = self.edges.iter().collect();
        edges.sort_unstable_by_key(|(id, _)| (id.first, id.second));

        for (k, v) in edges {
            // edgeID: u32, u32
            buf.extend_from_slice(&k.first.to_le_bytes());
            buf.extend_from_slice(&k.second.to_le_bytes());

            // EDGE
            buf.extend_from_slice(&v.serialize());
        }

        buf
    }
}

const P_IDX: u16 = 0;
const P_NAME: u16 = 1;
const P_OPCODE: u16 = 2;
const P_LINKAGE: u16 = 3;
const P_CALL_TYPE: u16 = 4;
const P_SOURCE_LOC: u16 = 5;
const P_SOURCE_FILE: u16 = 6;
const P_FUNCTION_TYPE: u16 = 7;
const P_ADDRESS_TAKEN: u16 = 8;

impl NodeProps {
    fn mask(&self) -> u16 {
        let mut mask: u16 = 0;
        mask |= (self.idx.is_some() as u16) << P_IDX;
        mask |= (self.name.is_some() as u16) << P_NAME;
        mask |= (self.opcode.is_some() as u16) << P_OPCODE;
        mask |= (self.linkage.is_some() as u16) << P_LINKAGE;
        mask |= (self.call_type.is_some() as u16) << P_CALL_TYPE;
        mask |= (self.source_loc.is_some() as u16) << P_SOURCE_LOC;
        mask |= (self.source_file.is_some() as u16) << P_SOURCE_FILE;
        mask |= (self.function_type.is_some() as u16) << P_FUNCTION_TYPE;
        mask |= ((self.address_taken == Some(true)) as u16) << P_ADDRESS_TAKEN;
        mask
    }
}

impl Node {
    pub fn serialize(&self, i: &mut Interner) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // 0 - type
        buf.push(self.ty as u8);

        // 1-2 - prop mask, little-endian
        buf.extend_from_slice(&self.props.mask().to_le_bytes());

        let props = &self.props;

        // u32: index prop
        if let Some(idx) = props.idx {
            buf.extend_from_slice(&idx.to_le_bytes());
        }

        // u32: interned string name
        if let Some(name) = &props.name {
            buf.extend_from_slice(&i.intern(name).to_le_bytes());
        }

        // u32 (interned): opcode
        if let Some(opcode) = &props.opcode {
            buf.extend_from_slice(&i.intern(opcode).to_le_bytes());
        }

        // u8: linkage
        if let Some(linkage) = props.linkage {
            buf.push(linkage as u8);
        }

        // u8: call_type
        if let Some(call_type) = props.call_type {
            buf.push(call_type as u8);
        }

        // u32 + u32: source_loc
        if let Some((first, second)) = props.source_loc {
            buf.extend_from_slice(&first.to_le_bytes());
            buf.extend_from_slice(&second.to_le_bytes());
        }

        // u32 (interned): source_file
        if let Some(source_file) = &props.source_file {
            buf.extend_from_slice(&i.intern(source_file).to_le_bytes());
        }

        // u32 (interned): function_type
        if let Some(function_type) = &props.function_type {
            buf.extend_from_slice(&i.intern(function_type).to_le_bytes());
        }

        // u8: address_taken
        // BIT PRESENCE IN MASK INDICATES TRUE

        buf
    }
}

impl Edge {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // edge kind bitset
        buf.push(self.kinds);

        buf
    }
}
