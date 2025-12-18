// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

#![feature(btree_cursors)]

mod remediate;
mod shadowobjs;
mod trace;

use libc::{Dl_info, atexit, c_void, dladdr, dlsym};
use std::ffi::CStr;
use std::fmt::Display;
use std::fs::File;
use std::io::{Seek, Write};
use std::sync::{LazyLock, RwLock};
use std::{env, process};

/// Appends id to base path, but before the first .suffix if any
fn idify_file_path(path: &str, id: impl Display) -> String {
    if let Some((stem, ext)) = path.rsplit_once('.') {
        format!("{}_{}.{}", stem, id, ext)
    } else {
        format!("{}_{}", path, id)
    }
}

pub struct MutexWrap<T> {
    mutex: RwLock<T>,
}

impl<T> MutexWrap<T> {
    pub const fn new(x: T) -> Self {
        MutexWrap {
            mutex: RwLock::new(x),
        }
    }

    // Abort if the mutex is poisoned
    pub fn lock(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.mutex.read().expect("Not poisoned")
    }

    pub fn lock_write(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.mutex.write().expect("Not poisoned")
    }
}

/// File for "resolve_dlsym.json"
pub static DLSYM_LOG_FILE: LazyLock<MutexWrap<File>> = LazyLock::new(|| {
    let path = env::var("RESOLVE_DLSYM_LOG");
    let path = path.unwrap_or_else(|_| "resolve_dlsym.json".to_string());

    let path = idify_file_path(&path, process::id());

    let mut file = File::create(path).unwrap();

    // Write JSON header only once, when the file is first opened
    let _ = write!(&mut file, "{{\n \"loaded_symbols\": [\n");

    // SAFETY: flush_dlsym_log is extern "C" and takes no arguments.
    // TODO: is DLSYM_LOG_FILE still valid during the atexit callback?
    unsafe { atexit(flush_dlsym_log) };

    MutexWrap::new(file)
});

#[used]
#[unsafe(link_section = ".init_array")]
static INIT_CTOR: extern "C" fn() = resolve_init;

#[unsafe(no_mangle)]
pub extern "C" fn resolve_init() {
    let mut builder = env_logger::builder();

    if cfg!(test) {
        builder.is_test(true);
    } else {
        let file = open_resolve_log_file();

        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }

    let _ = builder.try_init();
}

fn open_resolve_log_file() -> File {
    let path = env::var("RESOLVE_RUNTIME_LOG");
    let path = path.unwrap_or_else(|_| "resolve_log.out".to_string());

    let path = idify_file_path(&path, process::id());

    let file = File::create(path).unwrap();

    file
}

/**
 * @brief - Writes JSON footer to the file descriptor
 */
#[unsafe(no_mangle)]
pub extern "C" fn flush_dlsym_log() {
    let mut file = DLSYM_LOG_FILE.lock_write();

    // Seek back 2 bytse to erase last ",\n"
    file.seek_relative(-2).unwrap();

    let _ = write!(&mut file, "\n  ]\n}}\n");
}

/**
 * @brief - Records and resolves dynamically linked symbols using dlsym
 * @input - Pointer to dynamic loaded obj, name of symbol  
 * @return - C void type
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void {
    let addr = unsafe { dlsym(handle, symbol.cast()) };

    let lib_name = unsafe {
        let mut info: Dl_info = std::mem::zeroed();
        if dladdr(addr, &mut info) != 0 && !info.dli_fname.is_null() {
            CStr::from_ptr(info.dli_fname)
        } else {
            c"<unknown>"
        }
    };

    let symbol = if !symbol.is_null() {
        unsafe { CStr::from_ptr(symbol.cast::<i8>()) }
    } else {
        c"<null>"
    };

    let _ = writeln!(
        &mut DLSYM_LOG_FILE.lock_write(),
        "    {{ \"symbol\": \"{}\", \"library\": \"{}\" }},",
        symbol.to_str().unwrap_or("<invalid>"),
        lib_name.to_str().unwrap_or("<invalid>")
    );

    addr
}
