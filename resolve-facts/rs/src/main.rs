use std::collections::HashMap;

static VERSION: u8 = 0;

enum FactsMode {
    Full,
    Slim,
}

static MODE: FactsMode = FactsMode::Slim;

enum NodeType {
    Module,
    Function,
    Argument,
    BasicBlock,
    Instruction,
    GlobalVariable,
}

enum Linkage {
    Other,
    ExternalLinkage,
}

enum CallType {
    Direct,
    Indirect,
}

type NodeID = u32;

struct Node {
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

enum EdgeKind {
    Calls,
    Contains,
    DataFlowTo,
    References,
    EntryPoint,
    ControlFlowTo,
}

struct Edge {
    kinds: Vec<EdgeKind>,
}

struct EdgeID {
    first:  NodeID,
    second: NodeID,
}

struct ModuleFacts {
    nodes: HashMap<NodeID, ModuleFacts>,
    edges: HashMap<EdgeID, Edge>,
}

struct ProgramFacts {
    modules: HashMap<NodeID, ModuleFacts>,
}

fn main() {
    println!("Hello, world!");
}
