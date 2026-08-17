#[cfg(not(target_endian = "little"))]
compile_error!("the facts format currently requires a little-endian target");

mod builder;
mod interner;
mod reader;
mod schema;
mod utils;
mod writer;

pub use reader::*;
pub use schema::*;
pub use writer::FactsBuf;
