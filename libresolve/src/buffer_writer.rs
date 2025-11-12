// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for licensing information.

use core::fmt::Write;
use libc::{c_int, c_char, open, O_APPEND, O_WRONLY, O_CREAT, S_IRUSR, S_IWUSR};
use std::sync::{atomic::AtomicBool, LazyLock};
use std::env;
use std::ffi::CString;
use std::process;

pub struct BufferWriter<'a> {
    buf: &'a mut [u8],          
    pos: usize,                 // Current position (index) of buffer
}

impl<'a> Write for BufferWriter<'a> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        
        if self.pos + bytes.len() > self.buf.len() {
            return Err(core::fmt::Error)
        }

        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}

impl<'a> BufferWriter<'a> {
    pub fn new(buf: &'a mut [u8] ) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

}


// Used to avoid multiple headers
pub static WRITTEN_JSON_HEADER: AtomicBool = AtomicBool::new(false);

// FILE descriptor for "dlsym_log.json"
pub static DLSYM_FD: LazyLock<c_int> = LazyLock::new(|| {
    let pid = process::id();

    let base_path = env::var("RESOLVE_DLSYM_LOG")
            .unwrap_or_else(|_| "resolve_dlsym.json".to_string());
    
    let final_path = if let Some((stem, ext)) = base_path.rsplit_once('.') {
        format!("{}_{}.{}", stem, pid, ext)
    } else {
        format!("{}_{}", base_path, pid)
    };

    let c_path_str = CString::new(final_path).expect("Failed to convert path to CString");

    unsafe{
        open(
            c_path_str.as_ptr(),
            O_WRONLY | O_APPEND | O_CREAT,
            S_IRUSR  | S_IWUSR)
    }
});

// FILE descriptor for "resolve_log.out"
pub static RESOLVE_LOG_FD: LazyLock<c_int> = LazyLock::new(|| {
    let pid = process::id();
    
    let base_path = env::var("RESOLVE_RUNTIME_LOG")
            .unwrap_or_else(|_| "resolve_log.out".to_string());
    
    let final_path = if let Some((stem, ext)) = base_path.rsplit_once('.') {
        format!("{}_{}.{}", stem, pid, ext)
    } else {
        format!("{}_{}", base_path, pid)
    };
    
    let c_path_str = CString::new(final_path).expect("Failed to convert path to CString");
    
    unsafe {
        open (
            c_path_str.as_ptr(),
            O_WRONLY | O_APPEND | O_CREAT,
            S_IRUSR  | S_IWUSR
        )
    }
});

// FILE descriptor for "resolve_err_log.out"
pub static RESOLVE_ERR_LOG_FD: LazyLock<c_int> = LazyLock::new(|| unsafe {
    let pid = process::id();

    let base_path = env::var("RESOLVE_RUNTIME_ERR")
            .unwrap_or_else(|_| "resolve_err_log.out".to_string());
    
    let final_path = if let Some((stem, ext)) = base_path.rsplit_once('.') {
        format!("{}_{}.{}", stem, pid, ext)
    } else {
        format!("{}_{}", base_path, pid)
    };

    let c_path_str = CString::new(final_path).expect("Failed to convert path to CString");

    libc::open(
        c_path_str.as_ptr() as *const c_char,
        O_WRONLY | O_APPEND | O_CREAT,
        S_IRUSR  | S_IWUSR)
});
