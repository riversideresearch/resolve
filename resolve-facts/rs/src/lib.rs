#[cfg(not(target_endian = "little"))]
compile_error!("the facts format currently requires a little-endian target");

mod builder;
mod interner;
mod schema;
mod utils;
mod writer;

pub use builder::{FactsBuilder, ModuleHandle};
pub use schema::*;
pub use writer::FactsBuf;
