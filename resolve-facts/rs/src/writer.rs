use crate::model::*;

static VERSION: u8 = 0;

pub struct FactsBuf(Vec<u8>);

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_len(b: *mut FactsBuf) -> usize {
    unsafe { b.as_ref().unwrap().0.len() } // TODO: unwrap OK?
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_data(b: *mut FactsBuf) -> *const u8 {
    unsafe { b.as_ref().unwrap().0.as_ptr() } // TODO: unwrap OK?
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_free(b: *mut FactsBuf) {
    if !b.is_null() { unsafe {drop(Box::from_raw(b)); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_serialize(b: *const ProgramFacts) -> *mut FactsBuf {
    let Some(b) = (unsafe { b.as_ref() }) else { panic!("TODO") };

    Box::into_raw(Box::new(FactsBuf(b.serialize())))
}

impl ProgramFacts {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // 0 - version
        buf.push(VERSION);

        buf
    }
}