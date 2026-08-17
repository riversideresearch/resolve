use std::fs::read;
use std::io::Read;
use std::mem::*;
use std::path::{Path, PathBuf};

use object::{Object, ObjectSection};

use crate::schema::*;
use crate::writer::*;

const FACTS_SECTION: &str = ".facts";
const ZSTD_MAGIC: u32 = 0xfd2f_b528;
const ZSTD_SKIPPABLE_MAGIC: u32 = 0x184d_2a50;
const KNOWN_PROPERTIES: u32 = P_IDX
    | P_NAME
    | P_OPCODE
    | P_LINKAGE
    | P_CALL_TYPE
    | P_SOURCE_LOC
    | P_SOURCE_FILE
    | P_FUNCTION_TYPE
    | P_ADDRESS_TAKEN;
const KNOWN_EDGE_KINDS: u32 = (1 << EdgeKind::Calls as u8)
    | (1 << EdgeKind::Contains as u8)
    | (1 << EdgeKind::DataFlowTo as u8)
    | (1 << EdgeKind::References as u8)
    | (1 << EdgeKind::EntryPoint as u8)
    | (1 << EdgeKind::ControlFlowTo as u8);

#[derive(Debug)]
pub enum ReadError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Object {
        path: PathBuf,
        source: object::Error,
    },
    MissingFactsSection {
        path: PathBuf,
    },
    Decompression {
        path: PathBuf,
        source: std::io::Error,
    },
    UnalignedPayload {
        path: PathBuf,
        byte_len: usize,
    },
    InvalidFacts {
        path: PathBuf,
        source: InvalidFacts,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "could not read {}: {source}", path.display()),
            Self::Object { path, source } => {
                write!(f, "could not read ELF {}: {source}", path.display())
            }
            Self::MissingFactsSection { path } => {
                write!(f, "ELF {} has no {FACTS_SECTION} section", path.display())
            }
            Self::Decompression { path, source } => {
                write!(
                    f,
                    "could not decompress facts from {}: {source}",
                    path.display()
                )
            }
            Self::UnalignedPayload { path, byte_len } => write!(
                f,
                "facts from {} contain {byte_len} bytes, which is not divisible by 4",
                path.display()
            ),
            Self::InvalidFacts { path, source } => {
                write!(f, "invalid facts in {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Object { source, .. } => Some(source),
            Self::Decompression { source, .. } => Some(source),
            Self::InvalidFacts { source, .. } => Some(source),
            Self::MissingFactsSection { .. } | Self::UnalignedPayload { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidFacts {
    View {
        module: usize,
        byte_offset: usize,
        source: ViewError,
    },
    UnknownProperties {
        module: usize,
        node: NodeID,
        bits: u32,
    },
    InvalidNodeType {
        module: usize,
        node: NodeID,
        value: u8,
    },
    InvalidLinkage {
        module: usize,
        node: NodeID,
        value: u8,
    },
    InvalidCallType {
        module: usize,
        node: NodeID,
        value: u8,
    },
    InvalidStringOffset {
        module: usize,
        node: NodeID,
        property: &'static str,
        offset: u32,
    },
    InvalidUtf8 {
        module: usize,
        node: NodeID,
        property: &'static str,
        offset: u32,
    },
    InvalidEdgeEndpoint {
        module: usize,
        edge: usize,
        endpoint: NodeID,
        node_count: u32,
    },
    UnknownEdgeKinds {
        module: usize,
        edge: usize,
        bits: u32,
    },
    UnsortedEdges {
        module: usize,
        edge: usize,
    },
}

impl std::fmt::Display for InvalidFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::View {
                module,
                byte_offset,
                source,
            } => write!(
                f,
                "module {module} at byte {byte_offset} cannot be viewed: {source}"
            ),
            Self::UnknownProperties { module, node, bits } => write!(
                f,
                "module {module}, node {node} has unknown property bits {bits:#x}"
            ),
            Self::InvalidNodeType {
                module,
                node,
                value,
            } => write!(
                f,
                "module {module}, node {node} has invalid node type {value}"
            ),
            Self::InvalidLinkage {
                module,
                node,
                value,
            } => write!(
                f,
                "module {module}, node {node} has invalid linkage {value}"
            ),
            Self::InvalidCallType {
                module,
                node,
                value,
            } => write!(
                f,
                "module {module}, node {node} has invalid call type {value}"
            ),
            Self::InvalidStringOffset {
                module,
                node,
                property,
                offset,
            } => write!(
                f,
                "module {module}, node {node} has an invalid {property} string offset {offset}"
            ),
            Self::InvalidUtf8 {
                module,
                node,
                property,
                offset,
            } => write!(
                f,
                "module {module}, node {node} has non-UTF-8 {property} at string offset {offset}"
            ),
            Self::InvalidEdgeEndpoint {
                module,
                edge,
                endpoint,
                node_count,
            } => write!(
                f,
                "module {module}, edge {edge} refers to node {endpoint}, but the module has {node_count} nodes"
            ),
            Self::UnknownEdgeKinds { module, edge, bits } => write!(
                f,
                "module {module}, edge {edge} has unknown kind bits {bits:#x}"
            ),
            Self::UnsortedEdges { module, edge } => write!(
                f,
                "module {module}, edge {edge} is not strictly ordered after its predecessor"
            ),
        }
    }
}

impl std::error::Error for InvalidFacts {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::View { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl FactsBuf {
    pub fn read_file(path: impl AsRef<Path>) -> Result<Self, ReadError> {
        Self::read_files([path])
    }

    pub fn read_files<I, P>(paths: I) -> Result<Self, ReadError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut words = Vec::new();
        for path in paths {
            read_input(path.as_ref(), &mut words)?;
        }
        Ok(Self::from_words(words))
    }
}

fn read_input(path: &Path, words: &mut Vec<u32>) -> Result<(), ReadError> {
    let input = read(path).map_err(|source| ReadError::Io {
        path: path.to_owned(),
        source,
    })?;

    let payload = if input.starts_with(b"\x7fELF") {
        let object = object::File::parse(input.as_slice()).map_err(|source| ReadError::Object {
            path: path.to_owned(),
            source,
        })?;
        let section = object.section_by_name(FACTS_SECTION).ok_or_else(|| {
            ReadError::MissingFactsSection {
                path: path.to_owned(),
            }
        })?;
        section.data().map_err(|source| ReadError::Object {
            path: path.to_owned(),
            source,
        })?
    } else {
        input.as_slice()
    };

    let start = words.len();
    if is_zstd(payload) {
        let decoder = zstd::stream::read::Decoder::new(payload).map_err(|source| {
            ReadError::Decompression {
                path: path.to_owned(),
                source,
            }
        })?;
        append_reader(decoder, words).map_err(|error| match error {
            AppendError::Read(source) => ReadError::Decompression {
                path: path.to_owned(),
                source,
            },
            AppendError::Unaligned(byte_len) => ReadError::UnalignedPayload {
                path: path.to_owned(),
                byte_len,
            },
        })?;
    } else {
        append_bytes(payload, words).map_err(|byte_len| ReadError::UnalignedPayload {
            path: path.to_owned(),
            byte_len,
        })?;
    }

    let bytes = words_as_bytes(&words[start..]);
    validate(bytes).map_err(|source| ReadError::InvalidFacts {
        path: path.to_owned(),
        source,
    })
}

fn is_zstd(bytes: &[u8]) -> bool {
    let Some(magic) = bytes
        .get(..size_of::<u32>())
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };

    magic == ZSTD_MAGIC || magic & 0xffff_fff0 == ZSTD_SKIPPABLE_MAGIC
}

fn append_bytes(bytes: &[u8], words: &mut Vec<u32>) -> Result<(), usize> {
    if !bytes.len().is_multiple_of(size_of::<u32>()) {
        return Err(bytes.len());
    }

    words.reserve(bytes.len() / size_of::<u32>());
    for chunk in bytes.chunks_exact(size_of::<u32>()) {
        words.push(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    Ok(())
}

enum AppendError {
    Read(std::io::Error),
    Unaligned(usize),
}

fn append_reader(mut reader: impl Read, words: &mut Vec<u32>) -> Result<(), AppendError> {
    let mut buffer = [0; 64 * 1024];
    let mut pending = [0; size_of::<u32>()];
    let mut pending_len = 0;
    let mut byte_len = 0;

    loop {
        let read = reader.read(&mut buffer).map_err(AppendError::Read)?;
        if read == 0 {
            break;
        }
        byte_len += read;

        let mut bytes = &buffer[..read];
        if pending_len != 0 {
            let needed = size_of::<u32>() - pending_len;
            let copied = needed.min(bytes.len());
            pending[pending_len..pending_len + copied].copy_from_slice(&bytes[..copied]);
            pending_len += copied;
            bytes = &bytes[copied..];
            if pending_len == size_of::<u32>() {
                words.push(u32::from_le_bytes(pending));
            }
        }

        let mut chunks = bytes.chunks_exact(size_of::<u32>());
        words.extend(
            chunks
                .by_ref()
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap())),
        );
        let remainder = chunks.remainder();
        pending[..remainder.len()].copy_from_slice(remainder);
        pending_len = remainder.len();
    }

    if pending_len == 0 {
        Ok(())
    } else {
        Err(AppendError::Unaligned(byte_len))
    }
}

fn words_as_bytes(words: &[u32]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

fn validate(bytes: &[u8]) -> Result<(), InvalidFacts> {
    let mut remaining = bytes;
    let mut byte_offset = 0;
    let mut module_index = 0;

    while !remaining.is_empty() {
        let (module, rest) =
            ModuleRef::from_prefix(remaining).map_err(|source| InvalidFacts::View {
                module: module_index,
                byte_offset,
                source,
            })?;
        validate_module(module_index, module)?;
        byte_offset += module.as_bytes().len();
        module_index += 1;
        remaining = rest;
    }

    Ok(())
}

fn validate_module(module_index: usize, module: ModuleRef<'_>) -> Result<(), InvalidFacts> {
    for (node_index, node) in module.nodes().iter().enumerate() {
        let node_index = node_index as NodeID;
        let unknown = node.meta & PRESENT_MASK & !KNOWN_PROPERTIES;
        if unknown != 0 {
            return Err(InvalidFacts::UnknownProperties {
                module: module_index,
                node: node_index,
                bits: unknown,
            });
        }
        if node.node_type_raw() > NodeType::GlobalVariable as u8 {
            return Err(InvalidFacts::InvalidNodeType {
                module: module_index,
                node: node_index,
                value: node.node_type_raw(),
            });
        }
        if let Some(value) = node.linkage_raw()
            && value > Linkage::ExternalLinkage as u8
        {
            return Err(InvalidFacts::InvalidLinkage {
                module: module_index,
                node: node_index,
                value,
            });
        }
        if let Some(value) = node.call_type_raw()
            && value > CallType::Indirect as u8
        {
            return Err(InvalidFacts::InvalidCallType {
                module: module_index,
                node: node_index,
                value,
            });
        }

        validate_node_string(
            module_index,
            node_index,
            node,
            module,
            P_NAME,
            "name",
            node.name,
        )?;
        validate_node_string(
            module_index,
            node_index,
            node,
            module,
            P_OPCODE,
            "opcode",
            node.opcode,
        )?;
        validate_node_string(
            module_index,
            node_index,
            node,
            module,
            P_SOURCE_FILE,
            "source file",
            node.source_file,
        )?;
        validate_node_string(
            module_index,
            node_index,
            node,
            module,
            P_FUNCTION_TYPE,
            "function type",
            node.function_type,
        )?;
    }

    let node_count = module.header().node_count;
    let mut previous = None;
    for (edge_index, edge) in module.edges().iter().enumerate() {
        for endpoint in [edge.src, edge.dst] {
            if endpoint >= node_count {
                return Err(InvalidFacts::InvalidEdgeEndpoint {
                    module: module_index,
                    edge: edge_index,
                    endpoint,
                    node_count,
                });
            }
        }
        let unknown = edge.kinds & !KNOWN_EDGE_KINDS;
        if unknown != 0 {
            return Err(InvalidFacts::UnknownEdgeKinds {
                module: module_index,
                edge: edge_index,
                bits: unknown,
            });
        }
        let current = (edge.src, edge.dst);
        if previous.is_some_and(|previous| previous >= current) {
            return Err(InvalidFacts::UnsortedEdges {
                module: module_index,
                edge: edge_index,
            });
        }
        previous = Some(current);
    }

    Ok(())
}

fn validate_node_string(
    module_index: usize,
    node_index: NodeID,
    node: &Node,
    module: ModuleRef<'_>,
    present: u32,
    property: &'static str,
    id: Interned,
) -> Result<(), InvalidFacts> {
    if !node.has(present) {
        return Ok(());
    }

    let bytes = module
        .string_bytes(id)
        .ok_or(InvalidFacts::InvalidStringOffset {
            module: module_index,
            node: node_index,
            property,
            offset: id.0,
        })?;
    std::str::from_utf8(bytes).map_err(|_| InvalidFacts::InvalidUtf8 {
        module: module_index,
        node: node_index,
        property,
        offset: id.0,
    })?;
    Ok(())
}
