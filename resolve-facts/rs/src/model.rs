use std::collections::HashMap;

pub enum FactsMode {
    Full,
    Slim,
}

pub enum NodeType {
    Module,
    Function,
    Argument,
    BasicBlock,
    Instruction,
    GlobalVariable,
}

pub enum Linkage {
    Other,
    ExternalLinkage,
}

pub enum CallType {
    Direct,
    Indirect,
}

pub type NodeID = u32;
pub type ModuleID = u32;

pub struct Node {
    ty:             NodeType,
    idx:            Option<u32>,
    name:           Option<String>,
    opcode:         Option<String>,
    linkage:        Option<Linkage>,
    call_type:      Option<CallType>,
    source_loc:     Option<String>,
    source_file:    Option<String>,
    function_type:  Option<String>,
    address_taken:  Option<bool>,
}

pub enum EdgeKind {
    Calls,
    Contains,
    DataFlowTo,
    References,
    EntryPoint,
    ControlFlowTo,
}

pub struct Edge {
    kinds: Vec<EdgeKind>,
}

pub struct EdgeID {
    first:  NodeID,
    second: NodeID,
}

#[derive(Default)]
pub struct ModuleFacts {
    nodes: HashMap<NodeID, Node>,
    edges: HashMap<EdgeID, Edge>,
}

#[derive(Default)]
pub struct ProgramFacts {
    pub modules: HashMap<ModuleID, ModuleFacts>,
}