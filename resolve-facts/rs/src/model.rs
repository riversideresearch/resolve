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

pub struct NodeProps {
    pub idx:            Option<u32>,
    pub name:           Option<String>,
    pub opcode:         Option<String>,
    pub linkage:        Option<Linkage>,
    pub call_type:      Option<CallType>,
    pub source_loc:     Option<String>,
    pub source_file:    Option<String>,
    pub function_type:  Option<String>,
    pub address_taken:  Option<bool>,
}

pub struct Node {
    pub ty:     NodeType,
    pub props:  NodeProps,
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
    pub first:  NodeID,
    pub second: NodeID,
}

#[derive(Default)]
pub struct ModuleFacts {
    pub nodes: HashMap<NodeID, Node>,
    pub edges: HashMap<EdgeID, Edge>,
}

#[derive(Default)]
pub struct ProgramFacts {
    pub modules: HashMap<ModuleID, ModuleFacts>,
}