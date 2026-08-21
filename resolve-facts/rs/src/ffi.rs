use std::path::*;

use crate::schema::*;
use crate::utils::*;
use crate::writer::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FactsPath {
    pub data: *const u8,
    pub len: usize,
}

pub struct FactsReadError(String);

#[repr(C)]
#[derive(Debug)]
pub struct FactsReadResult {
    pub facts: *mut FactsBuf,
    pub error: *mut FactsReadError,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FactsModuleCursor {
    pub byte_offset: usize,
    pub module_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FactsModuleView {
    pub module_index: u32,
    pub nodes: *const Node,
    pub node_count: usize,
    pub edges: *const Edge,
    pub edge_count: usize,
    pub string_pool: *const u8,
    pub string_pool_len: usize,
}

impl FactsReadResult {
    fn success(facts: FactsBuf) -> Self {
        Self {
            facts: Box::into_raw(Box::new(facts)),
            error: std::ptr::null_mut(),
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            facts: std::ptr::null_mut(),
            error: Box::into_raw(Box::new(FactsReadError(message.into()))),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_read_files(paths: *const FactsPath, len: usize) -> FactsReadResult {
    let paths = if len == 0 {
        &[]
    } else if paths.is_null() {
        return FactsReadResult::error("null facts path array");
    } else {
        unsafe { std::slice::from_raw_parts(paths, len) }
    };

    let mut owned = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(path) = (unsafe { as_str(path.data, path.len) }) else {
            return FactsReadResult::error("facts paths must be valid UTF-8");
        };
        owned.push(PathBuf::from(path));
    }

    match FactsBuf::read_files(&owned) {
        Ok(facts) => FactsReadResult::success(facts),
        Err(error) => FactsReadResult::error(error.to_string()),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_read_error_len(error: *const FactsReadError) -> usize {
    unsafe { error.as_ref() }.map_or(0, |error| error.0.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_read_error_data(error: *const FactsReadError) -> *const u8 {
    unsafe { error.as_ref() }.map_or(std::ptr::null(), |error| error.0.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_read_error_free(error: *mut FactsReadError) {
    if !error.is_null() {
        unsafe {
            drop(Box::from_raw(error));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_module_next(
    facts: *const FactsBuf,
    cursor: *mut FactsModuleCursor,
    output: *mut FactsModuleView,
) -> bool {
    let Some(facts) = (unsafe { facts.as_ref() }) else {
        return false;
    };
    let Some(cursor) = (unsafe { cursor.as_mut() }) else {
        return false;
    };
    let Some(output) = (unsafe { output.as_mut() }) else {
        return false;
    };

    let bytes = facts.as_bytes();
    if cursor.byte_offset == bytes.len() {
        return false;
    }
    let Some(remaining) = bytes.get(cursor.byte_offset..) else {
        return false;
    };
    let Ok((module, _)) = ModuleRef::from_prefix(remaining) else {
        return false;
    };
    let Some(next_offset) = cursor.byte_offset.checked_add(module.as_bytes().len()) else {
        return false;
    };
    let Some(next_index) = cursor.module_index.checked_add(1) else {
        return false;
    };

    let nodes = module.nodes();
    let edges = module.edges();
    let string_pool = module.string_pool();
    *output = FactsModuleView {
        module_index: cursor.module_index,
        nodes: nodes.as_ptr(),
        node_count: nodes.len(),
        edges: edges.as_ptr(),
        edge_count: edges.len(),
        string_pool: string_pool.as_ptr(),
        string_pool_len: string_pool.len(),
    };
    cursor.byte_offset = next_offset;
    cursor.module_index = next_index;
    true
}
