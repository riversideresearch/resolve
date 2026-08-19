use std::{ffi::c_void, ptr::NonNull, slice};

use facts_rs::{FactsBuf, NodeID};

#[repr(C)]
struct ReachGraph {
    _private: [u8; 0],
}

#[repr(C)]
struct ReachQueryResult {
    _private: [u8; 0],
}

#[repr(C)]
struct ReachError {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct ReachNodeID {
    pub module: u32,
    pub node: NodeID,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReachEdgeType {
    DirectCall,
    IndirectCall,
    Contains,
    Successor,
    External,
    ExternalIndirectCall,
}

impl TryFrom<u8> for ReachEdgeType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DirectCall),
            1 => Ok(Self::IndirectCall),
            2 => Ok(Self::Contains),
            3 => Ok(Self::Successor),
            4 => Ok(Self::External),
            5 => Ok(Self::ExternalIndirectCall),
            _ => Err(format!("libreach returned unknown edge type {value}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachPath {
    pub nodes: Vec<ReachNodeID>,
    pub edges: Vec<ReachEdgeType>,
}

#[repr(C)]
struct ReachPathView {
    nodes: *const ReachNodeID,
    node_count: usize,
    edges: *const u8,
    edge_count: usize,
}

unsafe extern "C" {
    fn reach_graph_build(
        facts: *const c_void,
        options: *const (),
        error: *mut *mut ReachError,
    ) -> *mut ReachGraph;
    fn reach_graph_free(graph: *mut ReachGraph);
    fn reach_graph_edge_count(graph: *const ReachGraph) -> usize;

    fn reach_graph_query(
        graph: *const ReachGraph,
        src: ReachNodeID,
        dst: ReachNodeID,
        max_paths: usize,
        error: *mut *mut ReachError,
    ) -> *mut ReachQueryResult;
    fn reach_query_result_free(result: *mut ReachQueryResult);
    fn reach_query_result_path_count(result: *const ReachQueryResult) -> usize;
    fn reach_query_result_path(
        result: *const ReachQueryResult,
        index: usize,
        path: *mut ReachPathView,
    ) -> u8;

    fn reach_error_data(error: *const ReachError) -> *const u8;
    fn reach_error_len(error: *const ReachError) -> usize;
    fn reach_error_free(error: *mut ReachError);
}

pub struct Graph {
    raw: NonNull<ReachGraph>,
}

impl Graph {
    pub fn build(facts: &FactsBuf) -> Result<Self, String> {
        let mut error = std::ptr::null_mut();
        let graph = unsafe {
            reach_graph_build(
                std::ptr::from_ref(facts).cast(),
                std::ptr::null(),
                &mut error,
            )
        };

        match NonNull::new(graph) {
            Some(raw) => Ok(Self { raw }),
            None => Err(unsafe { take_error(error, "libreach could not build the graph") }),
        }
    }

    pub fn edge_count(&self) -> usize {
        unsafe { reach_graph_edge_count(self.raw.as_ptr()) }
    }

    pub fn query(
        &self,
        source: ReachNodeID,
        destination: ReachNodeID,
        max_paths: usize,
    ) -> Result<Vec<ReachPath>, String> {
        let mut error = std::ptr::null_mut();
        let result = unsafe {
            reach_graph_query(
                self.raw.as_ptr(),
                source,
                destination,
                max_paths,
                &mut error,
            )
        };
        let result = NonNull::new(result)
            .ok_or_else(|| unsafe { take_error(error, "libreach could not complete the query") })?;
        let result = QueryResult { raw: result };

        result.paths()
    }
}

impl Drop for Graph {
    fn drop(&mut self) {
        unsafe { reach_graph_free(self.raw.as_ptr()) };
    }
}

struct QueryResult {
    raw: NonNull<ReachQueryResult>,
}

impl QueryResult {
    fn paths(&self) -> Result<Vec<ReachPath>, String> {
        let path_count = unsafe { reach_query_result_path_count(self.raw.as_ptr()) };
        let mut paths = Vec::with_capacity(path_count);

        for index in 0..path_count {
            let mut view = ReachPathView {
                nodes: std::ptr::null(),
                node_count: 0,
                edges: std::ptr::null(),
                edge_count: 0,
            };
            let found = unsafe { reach_query_result_path(self.raw.as_ptr(), index, &mut view) };
            if found == 0 {
                return Err(format!("libreach did not return path {index}"));
            }

            let nodes = unsafe { slice_from_raw_parts(view.nodes, view.node_count) }.to_vec();
            let edges = unsafe { slice_from_raw_parts(view.edges, view.edge_count) }
                .iter()
                .copied()
                .map(ReachEdgeType::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            paths.push(ReachPath { nodes, edges });
        }

        Ok(paths)
    }
}

impl Drop for QueryResult {
    fn drop(&mut self) {
        unsafe { reach_query_result_free(self.raw.as_ptr()) };
    }
}

unsafe fn slice_from_raw_parts<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    }
}

unsafe fn take_error(error: *mut ReachError, fallback: &str) -> String {
    let Some(error) = NonNull::new(error) else {
        return fallback.to_owned();
    };
    let length = unsafe { reach_error_len(error.as_ptr()) };
    let data = unsafe { reach_error_data(error.as_ptr()) };
    let message = if data.is_null() {
        fallback.to_owned()
    } else {
        String::from_utf8_lossy(unsafe { slice::from_raw_parts(data, length) }).into_owned()
    };
    unsafe { reach_error_free(error.as_ptr()) };
    message
}

#[cfg(test)]
mod tests {
    use facts_rs::{EdgeKind, FactsBuilder, NodeType};

    use super::{Graph, ReachEdgeType, ReachNodeID};

    #[test]
    fn builds_and_queries_a_graph() {
        let mut builder = FactsBuilder::new();
        let module = builder.add_module(3);
        assert_eq!(builder.add_node(module, NodeType::Module), Some(0));
        let function = builder.add_node(module, NodeType::Function).unwrap();
        let block = builder.add_node(module, NodeType::BasicBlock).unwrap();
        assert!(builder.add_edge(module, function, block, EdgeKind::EntryPoint));

        let graph = Graph::build(&builder.freeze()).unwrap();
        let paths = graph
            .query(
                ReachNodeID {
                    module,
                    node: function,
                },
                ReachNodeID {
                    module,
                    node: block,
                },
                1,
            )
            .unwrap();

        assert_eq!(graph.edge_count(), 1);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].edges, vec![ReachEdgeType::Contains]);
    }
}
