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

    if let Some(m) = b.modules.get_mut(&module) {
        m.nodes.insert(
            node_id,
            Node { ty, props: NodeProps::default() }
        );
    }
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

// NODE PROP SPAM BELOW:
// - consumes strings as ptr with size

#[unsafe(no_mangle)]
pub extern "C" fn record_node_idx(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, idx: u32,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.idx = Some(idx);
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_name(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID,
    ptr: *const u8, len: usize,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    let Some(s) = (unsafe { as_str(ptr, len) }) else { return };
    node.props.name = Some(s.to_owned());
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_opcode(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID,
    ptr: *const u8, len: usize,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    let Some(s) = (unsafe { as_str(ptr, len) }) else { return };
    node.props.opcode = Some(s.to_owned());
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_linkage(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, linkage: Linkage,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.linkage = Some(linkage);
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_call_type(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, call_type: CallType,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.call_type = Some(call_type);
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_source_loc(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, line: u32, col: u32,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.source_loc = Some((line, col));
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_source_file(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID,
    ptr: *const u8, len: usize,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    let Some(s) = (unsafe { as_str(ptr, len) }) else { return };
    node.props.source_file = Some(s.to_owned());
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_function_type(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID,
    ptr: *const u8, len: usize,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    let Some(s) = (unsafe { as_str(ptr, len) }) else { return };
    node.props.function_type = Some(s.to_owned());
}

#[unsafe(no_mangle)]
pub extern "C" fn record_node_address_taken(
    b: *mut ProgramFacts, module: ModuleID, node_id: NodeID, address_taken: bool,
) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };
    let Some(node) = b.node_mut(module, node_id) else { return };
    node.props.address_taken = Some(address_taken);
}