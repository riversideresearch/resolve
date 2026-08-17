use std::collections::*;
use std::mem::*;

use crate::interner::*;
use crate::schema::*;
use crate::utils::*;
use crate::writer::*;

pub type ModuleHandle = u32;
pub const INVALID_ID: u32 = u32::MAX;

struct ModuleBuilder {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    pool: Interner,
    edge_indexes: HashMap<(NodeID, NodeID), usize>,
}

impl ModuleBuilder {
    fn new(hint: usize) -> Self {
        let edge_hint = hint.saturating_mul(2);
        Self {
            nodes: Vec::with_capacity(hint),
            edges: Vec::with_capacity(edge_hint),
            pool: Interner::default(),
            edge_indexes: HashMap::with_capacity(edge_hint),
        }
    }

    fn add_node(&mut self, ty: NodeType) -> NodeID {
        let dense_id = u32::try_from(self.nodes.len()).expect("module has too many nodes");
        self.nodes.push(Node::new(ty));
        dense_id
    }

    fn node_mut(&mut self, id: NodeID) -> Option<&mut Node> {
        self.nodes.get_mut(id as usize)
    }

    fn add_edge(&mut self, src: NodeID, dst: NodeID, kind: EdgeKind) -> bool {
        if src as usize >= self.nodes.len() || dst as usize >= self.nodes.len() {
            return false;
        }

        let id = (src, dst);
        let kind = 1u32 << kind as u8;
        if let Some(&index) = self.edge_indexes.get(&id) {
            self.edges[index].kinds |= kind;
            return true;
        }

        self.edge_indexes.insert(id, self.edges.len());
        self.edges.push(Edge {
            src,
            dst,
            kinds: kind,
        });
        true
    }

    fn intern_for_node(&mut self, id: NodeID, value: &str) -> Option<(NodeID, Interned)> {
        self.nodes.get(id as usize)?;
        let interned = self.pool.intern(value);
        Some((id, interned))
    }

    fn word_len(&self) -> usize {
        size_of::<ModuleHeader>() / size_of::<u32>()
            + self.nodes.len() * size_of::<Node>() / size_of::<u32>()
            + self.edges.len() * size_of::<Edge>() / size_of::<u32>()
            + self.pool.bytes().len().div_ceil(size_of::<u32>())
    }

    fn serialize_into(mut self, words: &mut Vec<u32>) {
        assert!(
            self.nodes
                .first()
                .is_some_and(|node| node.node_type_raw() == NodeType::Module as u8),
            "module node 0 must have type Module"
        );
        let pool_len = self.pool.bytes().len();
        let padded_pool_len = pool_len.checked_add(3).expect("intern pool is too large") & !3;
        let header = ModuleHeader {
            version: FORMAT_VERSION,
            node_count: u32::try_from(self.nodes.len()).expect("module has too many nodes"),
            edge_count: u32::try_from(self.edges.len()).expect("module has too many edges"),
            string_pool_len: u32::try_from(padded_pool_len)
                .expect("module intern pool exceeds 4 GiB"),
        };

        words.extend_from_slice(bytemuck::cast_slice(std::slice::from_ref(&header)));
        words.extend_from_slice(bytemuck::cast_slice(&self.nodes));

        self.edges.sort_unstable_by_key(|edge| (edge.src, edge.dst));
        words.extend_from_slice(bytemuck::cast_slice(&self.edges));

        for chunk in self.pool.bytes().chunks(size_of::<u32>()) {
            let mut bytes = [0; size_of::<u32>()];
            bytes[..chunk.len()].copy_from_slice(chunk);
            words.push(u32::from_ne_bytes(bytes));
        }
    }
}

#[derive(Default)]
pub struct FactsBuilder {
    modules: Vec<ModuleBuilder>,
}

impl FactsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_module(&mut self, hint: usize) -> ModuleHandle {
        let index = u32::try_from(self.modules.len()).expect("program has too many modules");
        self.modules.push(ModuleBuilder::new(hint));
        index
    }

    pub fn add_node(&mut self, module: ModuleHandle, ty: NodeType) -> Option<NodeID> {
        Some(self.module_mut(module)?.add_node(ty))
    }

    pub fn add_edge(
        &mut self,
        module: ModuleHandle,
        src: NodeID,
        dst: NodeID,
        kind: EdgeKind,
    ) -> bool {
        self.module_mut(module)
            .is_some_and(|module| module.add_edge(src, dst, kind))
    }

    pub fn set_node_idx(&mut self, module: ModuleHandle, node: NodeID, value: u32) -> bool {
        self.set_node(module, node, |node| {
            node.idx = value;
            node.set_present(P_IDX);
        })
    }

    pub fn set_node_name(&mut self, module: ModuleHandle, node: NodeID, value: &str) -> bool {
        self.set_node_string(module, node, value, |node, value| {
            node.name = value;
            node.set_present(P_NAME);
        })
    }

    pub fn set_node_opcode(&mut self, module: ModuleHandle, node: NodeID, value: &str) -> bool {
        self.set_node_string(module, node, value, |node, value| {
            node.opcode = value;
            node.set_present(P_OPCODE);
        })
    }

    pub fn set_node_linkage(&mut self, module: ModuleHandle, node: NodeID, value: Linkage) -> bool {
        self.set_node(module, node, |node| node.set_linkage(value))
    }

    pub fn set_node_call_type(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        value: CallType,
    ) -> bool {
        self.set_node(module, node, |node| node.set_call_type(value))
    }

    pub fn set_node_source_loc(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        line: u32,
        col: u32,
    ) -> bool {
        self.set_node(module, node, |node| {
            node.source_line = line;
            node.source_col = col;
            node.set_present(P_SOURCE_LOC);
        })
    }

    pub fn set_node_source_file(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        value: &str,
    ) -> bool {
        self.set_node_string(module, node, value, |node, value| {
            node.source_file = value;
            node.set_present(P_SOURCE_FILE);
        })
    }

    pub fn set_node_function_type(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        value: &str,
    ) -> bool {
        self.set_node_string(module, node, value, |node, value| {
            node.function_type = value;
            node.set_present(P_FUNCTION_TYPE);
        })
    }

    pub fn set_node_address_taken(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        value: bool,
    ) -> bool {
        self.set_node(module, node, |node| {
            if value {
                node.set_present(P_ADDRESS_TAKEN);
            } else {
                node.meta &= !P_ADDRESS_TAKEN;
            }
        })
    }

    pub fn freeze(self) -> FactsBuf {
        let capacity = self.modules.iter().map(ModuleBuilder::word_len).sum();
        let mut words = Vec::with_capacity(capacity);
        for module in self.modules {
            module.serialize_into(&mut words);
        }

        FactsBuf::from_words(words)
    }

    fn module_mut(&mut self, module: ModuleHandle) -> Option<&mut ModuleBuilder> {
        self.modules.get_mut(module as usize)
    }

    fn set_node(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        update: impl FnOnce(&mut Node),
    ) -> bool {
        let Some(node) = self
            .module_mut(module)
            .and_then(|module| module.node_mut(node))
        else {
            return false;
        };
        update(node);
        true
    }

    fn set_node_string(
        &mut self,
        module: ModuleHandle,
        node: NodeID,
        value: &str,
        update: impl FnOnce(&mut Node, Interned),
    ) -> bool {
        let Some(module) = self.module_mut(module) else {
            return false;
        };
        let Some((node, interned)) = module.intern_for_node(node, value) else {
            return false;
        };
        update(&mut module.nodes[node as usize], interned);
        true
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_new() -> *mut FactsBuilder {
    Box::into_raw(Box::new(FactsBuilder::new()))
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_free(builder: *mut FactsBuilder) {
    if !builder.is_null() {
        unsafe {
            drop(Box::from_raw(builder));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_add_module(
    builder: *mut FactsBuilder,
    hint: usize,
) -> ModuleHandle {
    unsafe { builder.as_mut() }.map_or(INVALID_ID, |builder| builder.add_module(hint))
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_add_node(
    builder: *mut FactsBuilder,
    module: ModuleHandle,
    ty: NodeType,
) -> NodeID {
    unsafe { builder.as_mut() }
        .and_then(|builder| builder.add_node(module, ty))
        .unwrap_or(INVALID_ID)
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_add_edge(
    builder: *mut FactsBuilder,
    module: ModuleHandle,
    src: NodeID,
    dst: NodeID,
    kind: EdgeKind,
) -> bool {
    unsafe { builder.as_mut() }.is_some_and(|builder| builder.add_edge(module, src, dst, kind))
}

macro_rules! ffi_node_setter {
    ($ffi:ident, $method:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $ffi(
            builder: *mut FactsBuilder,
            module: ModuleHandle,
            node: NodeID,
            value: $ty,
        ) -> bool {
            unsafe { builder.as_mut() }.is_some_and(|builder| builder.$method(module, node, value))
        }
    };
}

macro_rules! ffi_node_string_setter {
    ($ffi:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $ffi(
            builder: *mut FactsBuilder,
            module: ModuleHandle,
            node: NodeID,
            ptr: *const u8,
            len: usize,
        ) -> bool {
            let Some(builder) = (unsafe { builder.as_mut() }) else {
                return false;
            };
            let Some(value) = (unsafe { as_str(ptr, len) }) else {
                return false;
            };
            builder.$method(module, node, value)
        }
    };
}

ffi_node_setter!(facts_builder_set_node_idx, set_node_idx, u32);
ffi_node_string_setter!(facts_builder_set_node_name, set_node_name);
ffi_node_string_setter!(facts_builder_set_node_opcode, set_node_opcode);
ffi_node_setter!(facts_builder_set_node_linkage, set_node_linkage, Linkage);
ffi_node_setter!(
    facts_builder_set_node_call_type,
    set_node_call_type,
    CallType
);
ffi_node_string_setter!(facts_builder_set_node_source_file, set_node_source_file);
ffi_node_string_setter!(facts_builder_set_node_function_type, set_node_function_type);
ffi_node_setter!(
    facts_builder_set_node_address_taken,
    set_node_address_taken,
    bool
);

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_set_node_source_loc(
    builder: *mut FactsBuilder,
    module: ModuleHandle,
    node: NodeID,
    line: u32,
    col: u32,
) -> bool {
    unsafe { builder.as_mut() }
        .is_some_and(|builder| builder.set_node_source_loc(module, node, line, col))
}
