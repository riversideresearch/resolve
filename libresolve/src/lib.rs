// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
#![feature(sync_nonpoison)]
#![feature(nonpoison_mutex)]

mod remediate;
mod shadowobjs;
mod trace;

use libc::{Dl_info, atexit, c_void, dladdr, dlsym};
use std::ffi::CStr;
use std::fmt::Display;
use std::fs::File;
use std::io::{Seek, Write};
use std::sync::nonpoison::Mutex;
use std::sync::{LazyLock, Once};
use std::{env, process};

/// Appends id to base path, but before the first .suffix if any
fn idify_file_path(path: &str, id: impl Display) -> String {
    if let Some((stem, ext)) = path.rsplit_once('.') {
        format!("{}_{}.{}", stem, id, ext)
    } else {
        format!("{}_{}", path, id)
    }
}

/// File for "resolve_dlsym.json"
pub static DLSYM_LOG_FILE: LazyLock<Mutex<File>> = LazyLock::new(|| {
    let path = env::var("RESOLVE_DLSYM_LOG");
    let path = path.unwrap_or_else(|_| "resolve_dlsym.json".to_string());

    let path = idify_file_path(&path, process::id());

    Mutex::new(File::create(path).unwrap())
});

/// File for "resolve_log.out"
pub static RESOLVE_LOG_FILE: LazyLock<Mutex<File>> = LazyLock::new(|| {
    let path = env::var("RESOLVE_RUNTIME_LOG");
    let path = path.unwrap_or_else(|_| "resolve_log.out".to_string());

    let path = idify_file_path(&path, process::id());

    Mutex::new(File::create(path).unwrap())
});

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
    static REGISTER_EXIT: Once = Once::new();
    REGISTER_EXIT.call_once(|| {
        // SAFETY: flush_dlsym_log is extern "C" and takes no arguments.
        // TODO: is DLSYM_LOG_FILE still valid during the atexit callback?
        unsafe { atexit(flush_dlsym_log) };
    });

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

    // Write JSON header only once
    static WRITE_HEADER: Once = Once::new();
    WRITE_HEADER.call_once(|| {
        let _ = write!(&mut DLSYM_LOG_FILE.lock(), "{{\n \"loaded_symbols\": [\n");
    });

    let _ = writeln!(
        &mut DLSYM_LOG_FILE.lock(),
        "    {{ \"symbol\": \"{}\", \"library\": \"{}\" }},",
        symbol.to_str().unwrap_or("<invalid>"),
        lib_name.to_str().unwrap_or("<invalid>")
    );

    addr
}

#[cfg(test)]
mod tests {
    use crate::shadowobjs::{AllocType, ShadowObjectTable};

    #[test]
    fn test_add_and_print_shadow_objects() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x1000, 8);
        table.add_shadow_object(AllocType::Stack, 0x2000, 16);

        //table.print_shadow_obj();
    }

    #[test]
    fn test_remove_shadow_objects() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x1000, 8);
        table.add_shadow_object(AllocType::Stack, 0x2000, 16);
    }

    #[test]
    fn test_search_intersection_found() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Global, 0x3000, 4);

        let result = table.search_intersection(0x3002);
        assert!(result.is_some());
        assert_eq!(result.unwrap().alloc_type, AllocType::Global);
    }

    #[test]
    fn test_search_intersection_not_found() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x4000, 4);

        let result = table.search_intersection(0x5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_allocation() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Stack, 0x6000, 8);

        let typ = table.search_intersection(0x6004).unwrap().alloc_type;
        assert_eq!(typ, AllocType::Stack);

        let typ2 = table.search_intersection(0x7000).unwrap().alloc_type;
        assert_eq!(typ2, AllocType::Unallocated);
    }
    #[test]
    fn bounds_testing() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x8000, 8);

        //let range = table.bounds(0x8004).unwrap();
        //assert_eq!(range, 0x8000..=0x8007);
    }

    #[test]
    #[should_panic]
    fn test_bounds_invalid_address_panic() {
        // let table = ShadowObjectTable::new();
        //table.bounds(0xDEADBEEF).unwrap(); // should panic since there is no interesection
    }
}
