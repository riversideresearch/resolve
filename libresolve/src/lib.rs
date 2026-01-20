// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

#![feature(btree_cursors)]

mod remediate;
mod shadowobjs;
mod trace;

use libc::{Dl_info, atexit, c_void, dladdr, dlsym};
use std::ffi::{CStr, OsString};
use std::fmt::Display;
use std::fs::{self, File};
use std::path::PathBuf;
use std::io::{self, Seek, Write};
use std::sync::{LazyLock, Mutex};
use std::{env, process};

pub struct MutexWrap<T> {
    mutex: Mutex<T>,
}

impl<T> MutexWrap<T> {
    pub const fn new(x: T) -> Self {
        MutexWrap {
            mutex: Mutex::new(x),
        }
    }

    // Abort if the mutex is poisoned
    pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.mutex.lock().expect("Not poisoned")
    }
}

fn idify_file_path(path: &mut PathBuf, id: impl Display) {
    let file_name = path.file_name()
        .expect("Path could not be found in file system.")
        .to_owned();

    let mut updated_file_name = OsString::new();

    updated_file_name.push(file_name);
    updated_file_name.push("-");
    updated_file_name.push(id.to_string()); 

    path.set_file_name(updated_file_name);
}

/// File for "resolve_dlsym.json"
pub static DLSYM_LOG_FILE: LazyLock<MutexWrap<File>> = LazyLock::new(|| {
    let log_dir = env::var("RESOLVE_DLSYM_LOG_DIR")
        .unwrap_or_else(|_| ".".to_string());

    let mut path = PathBuf::from(log_dir);

    // Ensure the directory exists
    fs::create_dir_all(&path).expect("Cannot create parent directories.");

    path.push("resolve_dlsym.json");

    idify_file_path(&mut path, process::id());

    let mut file = File::create(&path).expect("Cannot create file in directory.");

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
        let file = open_resolve_log_file().unwrap_or_else(|err| { 
            eprintln!("Libresolve log file could not be created.");
            eprintln!("Error: {err:?}");
            process::exit(12);
        });
        
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }

    let _ = builder.try_init();
}

fn open_resolve_log_file() -> io::Result<File> {
    let log_dir = env::var("RESOLVE_RUNTIME_LOG_DIR")
        .unwrap_or_else(|_| ".".to_string());

    let mut path = PathBuf::from(log_dir);

    // Ensure the parent directories exist
    fs::create_dir_all(&path)?;
    
    // Append the file name
    path.push("resolve_log.out");

    idify_file_path(&mut path, process::id());
    File::create(&path)
}

/**
 * @brief - Writes JSON footer to the file descriptor
 */
#[unsafe(no_mangle)]
pub extern "C" fn flush_dlsym_log() {
    let mut file = DLSYM_LOG_FILE.lock();

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
        &mut DLSYM_LOG_FILE.lock(),
        "    {{ \"symbol\": \"{}\", \"library\": \"{}\" }},",
        symbol.to_str().unwrap_or("<invalid>"),
        lib_name.to_str().unwrap_or("<invalid>")
    );

    addr
}
