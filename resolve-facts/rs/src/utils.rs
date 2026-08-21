pub unsafe fn as_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).ok()
}
