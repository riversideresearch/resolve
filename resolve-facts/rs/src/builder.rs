use std::collections::*;

use crate::interner::*;
use crate::schema::*;
use crate::utils::*;

pub type ModuleHandle = u32;
pub const INVALID_ID: u32 = u32::MAX;

pub(crate) struct ModuleBuilder {
    pub(crate) nodes: Vec<Node>,
    pub(crate) edges: Vec<Edge>,
    pub(crate) pool: Interner,
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

    fn record_node(&mut self, ty: NodeType) -> NodeID {
        let dense_id = u32::try_from(self.nodes.len()).expect("module has too many nodes");
        self.nodes.push(Node::new(ty));
        dense_id
    }

    fn node_mut(&mut self, id: NodeID) -> Option<&mut Node> {
        self.nodes.get_mut(id as usize)
    }

    fn record_edge(&mut self, src: NodeID, dst: NodeID, kind: EdgeKind) {
        if src as usize >= self.nodes.len() || dst as usize >= self.nodes.len() {
            return;
        }

        let id = (src, dst);
        let kind = 1u32 << kind as u8;
        if let Some(&index) = self.edge_indexes.get(&id) {
            self.edges[index].kinds |= kind;
            return;
        }

        self.edge_indexes.insert(id, self.edges.len());
        self.edges.push(Edge {
            src,
            dst,
            kinds: kind,
        });
    }

    fn intern_for_node(&mut self, id: NodeID, value: &str) -> Option<(NodeID, Interned)> {
        self.nodes.get(id as usize)?;
        let interned = self.pool.intern(value);
        Some((id, interned))
    }
}

#[derive(Default)]
pub struct ProgramFacts {
    pub(crate) modules: Vec<ModuleBuilder>,
}

impl ProgramFacts {
    fn record_module(&mut self, hint: usize) -> ModuleHandle {
        let index = u32::try_from(self.modules.len()).expect("program has too many modules");
        self.modules.push(ModuleBuilder::new(hint));
        index
    }

    fn module_mut(&mut self, module: ModuleHandle) -> Option<&mut ModuleBuilder> {
        self.modules.get_mut(module as usize)
    }

    fn node_mut(&mut self, module: ModuleHandle, node: NodeID) -> Option<&mut Node> {
        self.module_mut(module)?.node_mut(node)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn new_program_facts() -> *mut ProgramFacts {
    Box::into_raw(Box::new(ProgramFacts::default()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_program_facts(b: *mut ProgramFacts) {
    if !b.is_null() {
        unsafe {
            drop(Box::from_raw(b));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn record_new_module(b: *mut ProgramFacts, hint: usize) -> ModuleHandle {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return INVALID_ID;
    };

    b.record_module(hint)
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node(b: *mut ProgramFacts, module: ModuleHandle, ty: NodeType) -> NodeID {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return INVALID_ID;
    };
    let Some(module) = b.module_mut(module) else {
        return INVALID_ID;
    };

    module.record_node(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn record_edge(
    b: *mut ProgramFacts,
    module: ModuleHandle,
    src: NodeID,
    dst: NodeID,
    kind: EdgeKind,
) {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return;
    };
    let Some(module) = b.module_mut(module) else {
        return;
    };

    module.record_edge(src, dst, kind);
}

macro_rules! node_scalar_setter {
    ($fn:ident, $field:ident, $present:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $fn(
            b: *mut ProgramFacts,
            module: ModuleHandle,
            node_id: NodeID,
            value: $ty,
        ) {
            let Some(b) = (unsafe { b.as_mut() }) else {
                return;
            };
            let Some(node) = b.node_mut(module, node_id) else {
                return;
            };

            node.$field = value;
            node.set_present($present);
        }
    };
}

macro_rules! node_string_setter {
    ($fn:ident, $field:ident, $present:ident) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $fn(
            b: *mut ProgramFacts,
            module: ModuleHandle,
            node_id: NodeID,
            ptr: *const u8,
            len: usize,
        ) {
            let Some(b) = (unsafe { b.as_mut() }) else {
                return;
            };
            let Some(value) = (unsafe { as_str(ptr, len) }) else {
                return;
            };
            let Some(module) = b.module_mut(module) else {
                return;
            };
            let Some((dense_id, interned)) = module.intern_for_node(node_id, value) else {
                return;
            };

            let node = &mut module.nodes[dense_id as usize];
            node.$field = interned;
            node.set_present($present);
        }
    };
}

node_scalar_setter!(record_node_idx, idx, P_IDX, u32);
node_string_setter!(record_node_name, name, P_NAME);
node_string_setter!(record_node_opcode, opcode, P_OPCODE);
node_string_setter!(record_node_source_file, source_file, P_SOURCE_FILE);
node_string_setter!(record_node_function_type, function_type, P_FUNCTION_TYPE);

#[unsafe(no_mangle)]
pub extern "C" fn record_node_linkage(
    b: *mut ProgramFacts,
    module: ModuleHandle,
    node_id: NodeID,
    value: Linkage,
) {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return;
    };
    let Some(node) = b.node_mut(module, node_id) else {
        return;
    };
    node.set_linkage(value);
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_call_type(
    b: *mut ProgramFacts,
    module: ModuleHandle,
    node_id: NodeID,
    value: CallType,
) {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return;
    };
    let Some(node) = b.node_mut(module, node_id) else {
        return;
    };
    node.set_call_type(value);
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_address_taken(
    b: *mut ProgramFacts,
    module: ModuleHandle,
    node_id: NodeID,
    value: bool,
) {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return;
    };
    let Some(node) = b.node_mut(module, node_id) else {
        return;
    };

    if value {
        node.set_present(P_ADDRESS_TAKEN);
    } else {
        node.meta &= !P_ADDRESS_TAKEN;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_source_loc(
    b: *mut ProgramFacts,
    module: ModuleHandle,
    node_id: NodeID,
    line: u32,
    col: u32,
) {
    let Some(b) = (unsafe { b.as_mut() }) else {
        return;
    };
    let Some(node) = b.node_mut(module, node_id) else {
        return;
    };

    node.source_line = line;
    node.source_col = col;
    node.set_present(P_SOURCE_LOC);
}
