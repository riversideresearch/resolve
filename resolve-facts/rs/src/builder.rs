use crate::model::*;
use crate::utils::*;

#[unsafe(no_mangle)]
pub extern "C" fn new_program_facts() -> *mut ProgramFacts {
    Box::into_raw(Box::new(ProgramFacts::default()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_program_facts(b: *mut ProgramFacts) {
    if !b.is_null() { unsafe {drop(Box::from_raw(b)); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn record_new_module(b: *mut ProgramFacts, id: ModuleID, hint: usize) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };

    b.modules.reserve(hint);
    b.modules.insert(id, ModuleFacts::default());
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node(b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, ty: NodeType) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };

    b.modules
        .entry(module)
        .or_default()
        .nodes
        .insert(node_id, Node { ty, props: NodeProps::default() });
}

#[unsafe(no_mangle)]
pub extern "C" fn record_edge(
    b: *mut ProgramFacts, module: ModuleID,
    src: NodeID, dst: NodeID, kind: EdgeKind
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(m) = b.modules.get_mut(&module) else {return };
    let edge = m.edges.entry(EdgeID { first: src, second: dst }).or_default();
    edge.kinds |= 1u8 << (kind as u8);
}

// NODE PROPS:
// note: I was trying to come up with a way to generate this ABI
//       (the C++ used visitor pattern with llambdas) cleanly, and
//       Opus came up with this macro magic. Seems solid to me :)
macro_rules! node_prop_setter {
    // string fields: (ptr, len)
    ($fn:ident, $field:ident, str) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $fn(
            b: *mut ProgramFacts, module: ModuleID, node_id: NodeID,
            ptr: *const u8, len: usize,
        ) {
            let Some(b) = (unsafe { b.as_mut() }) else { return };
            let Some(node) = b.node_mut(module, node_id) else { return };
            let Some(s) = (unsafe { as_str(ptr, len) }) else { return };
            node.props.$field = Some(s.to_owned());
        }
    };
    // scalar / enum / bool fields, passed by value
    ($fn:ident, $field:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $fn(
            b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, value: $ty,
        ) {
            let Some(b) = (unsafe { b.as_mut() }) else { return };
            let Some(node) = b.node_mut(module, node_id) else { return };
            node.props.$field = Some(value);
        }
    };
}

node_prop_setter!(record_node_idx,           idx,           u32);
node_prop_setter!(record_node_linkage,       linkage,       Linkage);
node_prop_setter!(record_node_call_type,     call_type,     CallType);
node_prop_setter!(record_node_address_taken, address_taken, bool);
node_prop_setter!(record_node_name,          name,          str);
node_prop_setter!(record_node_opcode,        opcode,        str);
node_prop_setter!(record_node_source_file,   source_file,   str);
node_prop_setter!(record_node_function_type, function_type, str);

#[unsafe(no_mangle)]
pub extern "C" fn record_node_source_loc(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, line: u32, col: u32,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.source_loc = Some((line, col));
}