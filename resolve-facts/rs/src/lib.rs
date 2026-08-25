#[cfg(not(target_endian = "little"))]
compile_error!("the facts format currently requires a little-endian target");

mod builder;
mod ffi;
mod interner;
mod reader;
mod schema;
mod utils;
mod writer;

pub use builder::{FactsBuilder, ModuleHandle};
pub use reader::*;
pub use schema::*;
pub use writer::FactsBuf;
