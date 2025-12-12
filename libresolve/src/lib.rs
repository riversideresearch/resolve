// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
#![feature(sync_nonpoison)]
#![feature(nonpoison_mutex)]

mod buffer_writer;
mod shadowobjs;
mod remediate;
mod trace;

use libc::{atexit, c_void, dladdr, dlsym, lseek, write, Dl_info, SEEK_END};
use std::io::Write;
use std::ffi::CStr;
use std::sync::atomic::Ordering;
use std::sync::Once;

use crate::buffer_writer::{BufferWriter, DLSYM_FD, RESOLVE_LOG_FILE, WRITTEN_JSON_HEADER};

static REGISTER: Once = Once::new();

fn register_cleanup() {
    unsafe {
        // SAFETY: flush_dlsym_log is extern "C" and takes no arguments.
        atexit(flush_dlsym_log);
    }
}

/**
 * @brief - Records and resolves dynamically linked symbols using dlsym
 * @input - Pointer to dynamic loaded obj, name of symbol  
 * @return - C void type
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_dlsym(handle: *mut c_void, symbol: *const u8) -> *mut c_void {
    
    REGISTER.call_once(|| {
        register_cleanup();
    });
    
    let addr = unsafe { dlsym(handle, symbol.cast()) };
    
    let origin_lib = unsafe {
        let mut info: Dl_info = std::mem::zeroed();
        let origin = if dladdr(addr, &mut info) != 0 && !info.dli_fname.is_null() {
            info.dli_fname
        } else  {
            b"<unknown>\0".as_ptr().cast::<i8>()
        };

        origin
    };
    
    let symbol_str = if !symbol.is_null() {
        unsafe { CStr::from_ptr(symbol.cast::<i8>()).to_bytes() }
    } else {
        b"<null>\0"
    };

    let lib_str = unsafe { CStr::from_ptr(origin_lib).to_bytes() }; 

    // Write JSON header only once 
    if WRITTEN_JSON_HEADER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok() 
    {
        let header = b"{\n \"loaded_symbols\": [\n";
        let _ = unsafe{ write(*DLSYM_FD, header.as_ptr() as *const _, header.len()) };
    }


    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(
        &mut writer,
        "    {{ \"symbol\": \"{}\", \"library\": \"{}\" }},",
        core::str::from_utf8(symbol_str).unwrap_or("<invalid>"),
        core::str::from_utf8(lib_str).unwrap_or("<invalid>")
    );


    let json_bytes = writer.as_bytes();
    let _ = unsafe { write(*DLSYM_FD, json_bytes.as_ptr() as *const _, json_bytes.len()) };
    
    addr

} 
/**
 * @brief - Writes JSON footer to the file descriptor
 */
#[unsafe(no_mangle)]
pub extern "C" fn flush_dlsym_log() {
    unsafe {
        // Seek back 2 bytse to erase last ",\n"
        if lseek(*DLSYM_FD, -2, SEEK_END) == -1 {
            // 
            let fallback = b"  ";
            let _ = write(*DLSYM_FD, fallback.as_ptr() as *const _, fallback.len());
            return;
        }

        let footer = b"\n  ]\n}\n";
        let _ = write(*DLSYM_FD, footer.as_ptr() as *const _, footer.len());
    }
}

#[cfg(test)]
mod tests {
    use crate::shadowobjs::{ShadowObjectTable, AllocType};

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