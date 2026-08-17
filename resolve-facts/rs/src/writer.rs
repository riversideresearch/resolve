use crate::builder::*;
use crate::schema::*;

#[derive(Debug, Default)]
pub struct FactsBuf(Vec<u32>);

impl FactsBuf {
    pub(crate) fn from_words(words: Vec<u32>) -> Self {
        Self(words)
    }

    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(&self.0)
    }

    pub fn view(&self) -> FactsRef<'_> {
        FactsRef::new(self.as_bytes())
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_len(b: *const FactsBuf) -> usize {
    unsafe { b.as_ref() }.map_or(0, |buf| buf.as_bytes().len())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_data(b: *const FactsBuf) -> *const u8 {
    unsafe { b.as_ref() }.map_or(std::ptr::null(), |buf| buf.as_bytes().as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_buf_free(b: *mut FactsBuf) {
    if !b.is_null() {
        unsafe {
            drop(Box::from_raw(b));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn facts_builder_freeze(builder: *mut FactsBuilder) -> *mut FactsBuf {
    if builder.is_null() {
        return std::ptr::null_mut();
    }

    let builder = unsafe { Box::from_raw(builder) };
    Box::into_raw(Box::new(builder.freeze()))
}
