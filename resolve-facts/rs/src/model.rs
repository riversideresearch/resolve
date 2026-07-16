use std::collections::HashMap;

#[allow(unused)] // cbindgen ABI
#[repr(u8)]
pub enum NodeType {
    Module,
    Function,
    Argument,
    BasicBlock,
    Instruction,
    GlobalVariable,
}

#[allow(unused)] // cbindgen ABI
#[repr(u8)]
pub enum Linkage {
    Other,
    ExternalLinkage,
}

#[allow(unused)] // cbindgen ABI
#[repr(u8)]
pub enum CallType {
    Direct,
    Indirect,
}

pub type NodeID = u32;
pub type ModuleID = u32;

#[derive(Default)]
pub struct NodeProps {
    pub idx:            Option<u32>,
    pub name:           Option<String>,
    pub opcode:         Option<String>,
    pub linkage:        Option<Linkage>,
    pub call_type:      Option<CallType>,
    pub source_loc:     Option<(u32, u32)>,
    pub source_file:    Option<String>,
    pub function_type:  Option<String>,
    pub address_taken:  Option<bool>,
}

pub struct Node {
    pub ty:     NodeType,
    pub props:  NodeProps,
}

#[allow(unused)] // cbindgen ABI
#[repr(u8)]
pub enum EdgeKind {
    Calls,
    Contains,
    DataFlowTo,
    References,
    EntryPoint,
    ControlFlowTo,
}

#[derive(Default)]
pub struct Edge {
    pub kinds: u8, // EdgeKind bitset
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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

impl ProgramFacts {
    pub fn node_mut(&mut self, module: ModuleID, node: NodeID) -> Option<&mut Node> {
        self.modules.get_mut(&module)?.nodes.get_mut(&node)
    }
}