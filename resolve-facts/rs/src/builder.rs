use crate::model::*;

#[unsafe(no_mangle)]
pub extern "C" fn new_facts() -> *mut ProgramFacts {
    Box::into_raw(Box::new(ProgramFacts::default()))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_facts(b: *mut ProgramFacts) {
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

    
}

#[unsafe(no_mangle)] // TODO: UPDATE FUNC??
pub extern "C" fn record_node_prop(b: *mut ProgramFacts, module: ModuleID, node_id: NodeID) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };


}

#[unsafe(no_mangle)]
pub extern "C" fn record_edge(b: *mut ProgramFacts, module: ModuleID,) {
    let Some(b) = (unsafe { b.as_mut() }) else { return };


}