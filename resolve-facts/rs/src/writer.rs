use std::mem::*;

use crate::builder::*;
use crate::schema::*;

#[derive(Debug, Default)]
pub struct FactsBuf(Vec<u32>);

impl FactsBuf {
    pub(crate) fn from_words(words: Vec<u32>) -> Self {
        Self(words)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.0.as_ptr().cast::<u8>(),
                self.0.len() * size_of::<u32>(),
            )
        }
    }

    pub fn view(&self) -> FactsRef<'_> {
        FactsRef::new(self.as_bytes())
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_len(b: *const FactsBuf) -> usize {
    unsafe { b.as_ref() }.map_or(0, |buf| buf.as_bytes().len())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_data(b: *const FactsBuf) -> *const u8 {
    unsafe { b.as_ref() }.map_or(std::ptr::null(), |buf| buf.as_bytes().as_ptr())
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
pub extern "C" fn facts_freeze(b: *mut ProgramFacts) -> *mut FactsBuf {
    if b.is_null() {
        return std::ptr::null_mut();
    }

    let b = unsafe { Box::from_raw(b) };
    Box::into_raw(Box::new(b.freeze()))
}

impl ProgramFacts {
    pub fn freeze(self) -> FactsBuf {
        let capacity = self.modules.iter().map(ModuleBuilder::word_len).sum();
        let mut words = Vec::with_capacity(capacity);
        for module in self.modules {
            module.serialize_into(&mut words);
        }

        FactsBuf(words)
    }
}

impl ModuleBuilder {
    fn word_len(&self) -> usize {
        size_of::<ModuleHeader>() / size_of::<u32>()
            + self.nodes.len() * size_of::<Node>() / size_of::<u32>()
            + self.edges.len() * size_of::<Edge>() / size_of::<u32>()
            + self.pool.bytes().len().div_ceil(size_of::<u32>())
    }

    fn serialize_into(mut self, words: &mut Vec<u32>) {
        let pool_len = self.pool.bytes().len();
        let padded_pool_len = pool_len.checked_add(3).expect("intern pool is too large") & !3;
        let header = ModuleHeader {
            version: FORMAT_VERSION,
            node_count: u32::try_from(self.nodes.len()).expect("module has too many nodes"),
            edge_count: u32::try_from(self.edges.len()).expect("module has too many edges"),
            string_pool_len: u32::try_from(padded_pool_len)
                .expect("module intern pool exceeds 4 GiB"),
        };

        push_header(words, &header);
        for node in &self.nodes {
            push_node(words, node);
        }

        self.edges.sort_unstable_by_key(|edge| (edge.src, edge.dst));
        for edge in &self.edges {
            push_edge(words, edge);
        }

        for chunk in self.pool.bytes().chunks(size_of::<u32>()) {
            let mut bytes = [0; size_of::<u32>()];
            bytes[..chunk.len()].copy_from_slice(chunk);
            words.push(u32::from_ne_bytes(bytes));
        }
    }
}

fn push_header(words: &mut Vec<u32>, header: &ModuleHeader) {
    words.extend_from_slice(&[
        header.version,
        header.node_count,
        header.edge_count,
        header.string_pool_len,
    ]);
}

fn push_node(words: &mut Vec<u32>, node: &Node) {
    words.extend_from_slice(&[
        node.meta,
        node.idx,
        node.name.0,
        node.opcode.0,
        node.source_line,
        node.source_col,
        node.source_file.0,
        node.function_type.0,
    ]);
}

fn push_edge(words: &mut Vec<u32>, edge: &Edge) {
    words.extend_from_slice(&[edge.src, edge.dst, edge.kinds]);
}
