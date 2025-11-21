// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

mod shadowobjs;
mod buffer_writer;

use libc::{atexit, c_char, c_float, c_void, calloc, dladdr, dlsym, free, lseek, malloc, memcpy, realloc, strdup, strndup, strlen, write, Dl_info, SEEK_END};
use core::fmt::Write;
use std::fmt::Display;
use std::ffi::CStr;
use std::sync::atomic::Ordering;
use std::sync::Once;

use crate::buffer_writer::{BufferWriter, DLSYM_FD, RESOLVE_LOG_FD, RESOLVE_ERR_LOG_FD, WRITTEN_JSON_HEADER};
use crate::shadowobjs::{ShadowObject, AllocType, Vaddr, ALIVE_OBJ_LIST, FREED_OBJ_LIST};


/**
 * NOTE
 * Libresolve supports adding shadow objects for stack objects
 * but we do not currently support removing stack objects from 
 * ALIVE_OBJ_LIST once the stack objects are freed at the end
 * of a function scope
 **/

/**
 * @brief - Allocator interface for stack objects
 * @input - size of the pointer allocation in bytes 
 * @return - none 
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_stack_obj(ptr: *mut c_void, size: usize) -> () {
    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    obj_list.add_shadow_object(AllocType::Stack, ptr as Vaddr, size);

    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let _ = writeln!(&mut writer, "[STACK] Logging stack allocated object: {}", ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe {libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };
}

/**
 * @brief - Allocator logging interface for malloc 
 * @input - size of the allocation in bytes
 * @return - ptr to the allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_malloc(size: usize) -> *mut c_void {
    let ptr = unsafe { malloc(size + 1) };
    
    if ptr.is_null() {
        return ptr
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let _ = writeln!(&mut writer, "[HEAP] Object allocated with size: {}, address: 0x{:x}", size, ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    // Return the pointer  
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_gep(ptr: *mut c_void, derived: *mut c_void) -> *mut c_void {
    let sobj_table = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");

    // Look up the shadow object corresponding to this access.
    // NOTE: Return 0 ('null') if shadow object cannot be found.
    let Some(sobj) = sobj_table.search_intersection(ptr as Vaddr) else { return 0 as *mut c_void; };

    // If shadow object exists then check if the access is within bounds
    if sobj.contains(derived as Vaddr) {
        return derived as *mut c_void
    } 

    // Return 1-past limit of allocation @ ptr
    sobj.past_limit() as *mut c_void
}

/**
 * @brief - Allocator logging interface for memcpy 
 * @input
 *  - dest: pointer to be copied to 
 *  - src: pointer to be copied from
 *  - size: size of the allocation in bytes  
 * @return - ptr to the allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_memcpy(dest: *mut c_void, src: *mut c_void, size: usize) -> *mut c_void {   
    let ptr = unsafe { memcpy(dest, src, size) };

    if ptr.is_null() {
        return ptr
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[HEAP] Object copied to dst: {:?}, from src {:?}, with size: {}, ptr: 0x{:x}", dest, src, size, ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    ptr
}

/**
 * @brief - Allocator logging interface for free 
 * @input - ptr to the allocation
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_free(ptr: *mut c_void) -> () {
    let obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    
    // // Insert a function to find the object and return the pointer size
    // // Do I need to handle if the sobj cannot be found? 
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[FREE] Allocated object freed at address: 0x{:x}", ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    // Lookup shadow object
    let sobj_opt = obj_list.search_intersection(ptr as Vaddr);
    let ptr_size: usize;

    // Check if the shadow object exists
    match sobj_opt {
        Some(sobj) => {
            ptr_size = sobj.limit;

            let mut writer = BufferWriter::new(&mut buf);
            let _ = writeln!(
                &mut writer,
                "[INFO] Found shadow object for allocated object, 0x{:x}, size = {}",
                ptr as Vaddr,
                ptr_size
            );
            let written = writer.as_bytes();
            unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
        }
        None => {
            ptr_size = 0;
            let mut writer = BufferWriter::new(&mut buf);
            let _ = writeln!(
                &mut writer,
                "[WARNING] No shadow object found for allocated object: 0x{:x}",
                ptr as Vaddr
        );
        let written = writer.as_bytes();
        unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
        }
    }

    // release lock before taking another lock
    drop(obj_list);
    
    // TODO: Remove object from alive list?
    // Insert shadow object into freed object list
    let mut freed_guard = FREED_OBJ_LIST.lock().expect("Mutex not poisoned");
    freed_guard.add_shadow_object(AllocType::Unallocated, ptr as Vaddr, ptr_size);

    let _ = unsafe { free(ptr) };
    
}

/**
 * @brief - Allocator logging interface for realloc 
 * @input 
 *  - ptr: ptr to the original allocation
 *  - size: size of the allocation in bytes 
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let realloc_ptr = unsafe { realloc(ptr, size) };

    if realloc_ptr.is_null() {
        return realloc_ptr
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    obj_list.add_shadow_object(AllocType::Heap, realloc_ptr as Vaddr, size);

    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[HEAP] Allocated object reallocated mem from src: {:?}, size: {}, dst ptr: 0x{:x}", ptr, size, realloc_ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    realloc_ptr
}

/**
 * @brief - Allocator logging interface for calloc 
 * @input 
 *  - n_items: number of items in the allocation
 *  - size: size of the allocation in bytes 
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_calloc(n_items: usize, size: usize) -> *mut c_void {   
    let ptr = unsafe { calloc(n_items, size) };

    if ptr.is_null() {
        return ptr
    }


    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[HEAP] Logging allocation with {} items, size (bytes): {}, dst ptr: 0x{:x}", n_items, size, ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };


    ptr
}

/**
 * @brief - Allocator logging interface for strdup 
 * @input 
 *  - ptr: ptr to the original allocation
 * @return - pointer to the copied string
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_strdup(ptr: *mut c_char) -> *mut c_char {
    let string_ptr = unsafe { strdup(ptr) };

    if string_ptr.is_null() {
        return string_ptr
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    let sizeofstr = unsafe { strlen(ptr) + 1}; // NOTE: +1 for null terminate byte string in C
    obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);

     let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[HEAP] Logging 'strdup' function call with dst ptr: 0x{:x}", string_ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    string_ptr
}


/**
 * @brief - Allocator logging interface for strdup 
 * @input 
 *  - ptr: ptr to the original allocation
 *  - size: number of bytes to copied
 * @return - pointer to the copied string
 * NOTE: Read this link to understand the nature of strdup & strndup
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/strdup.html
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_strndup(ptr: *mut c_char, size: usize) -> *mut c_char {
    let string_ptr = unsafe { strndup(ptr, size) };

    if string_ptr.is_null() {
        return string_ptr
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    let sizeofstr = unsafe { strlen(ptr) + 1};
    obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);

     let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let _ = writeln!(&mut writer, "[HEAP] Logging 'strndup' function call with size (bytes): {}, dst ptr: {:?}", size, string_ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len()) };

    string_ptr
}

pub fn libresolve_arg<T: Display>(arg: T, funct_name: *const u8) {
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);


    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[ARG] Function name: {}, value: {}", funct_str, arg);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

pub fn libresolve_ret<T: Display>(ret: T, funct_name: *const u8) {
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);


    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[RET] Function name: {}, value: {}", funct_str, ret);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i8(arg: i8, funct_name: *const u8)
{
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i16(arg: i16, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i32(arg: i32, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i64(arg: i64, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_float(arg: c_float, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_ptr(arg: *mut c_void, funct_name: *const u8) {
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[ARG] Function name: {}, value(pointer): {:?}", funct_str, arg);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_opaque(funct_name: *const u8) {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let funct_str = unsafe {
        if funct_name.is_null() {
            "[invalid pointer]"
        } else {
            CStr::from_ptr(funct_name as *const c_char)
                .to_str()
                .unwrap_or("[invalid utf8]")
        }
    };

    let _ = writeln!(
        &mut writer,
        "[ARG] Function {:?} has a runtime argument with opaque type, size: in progress",
        funct_str
    );

    let written = writer.as_bytes();
    unsafe {
        libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len());
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i8(ret: i8, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i16(ret: i16, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i32(ret: i32, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i64(ret: i64, funct_name: *const u8) 
{
   libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_float(ret: c_float, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_ptr(ret: *mut c_void, funct_name: *const u8) 
{
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };
    let _ = writeln!(&mut writer, "[RET] Function {} returned a pointer with address {:?}", funct_str, ret);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_void(funct_name: *const u8) 
{
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[RET] Function {} returned void", funct_str);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_bb(index: i64, funct_name: *const u8) 
{
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[BB] Basic block index: {}, transition from {}", index, funct_str);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_opaque(ptr: *mut c_void, funct_name: *const u8) {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const c_char)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut writer,
        "[RET] Function {:?} returned: {:?}",
        funct_str,
        ptr 
    );

    let written = writer.as_bytes();
    unsafe {
        libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len());
    }
}

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

/**
 * @brief - Verifies if pointer access is within memory bounds  
 * @input 
 *  - base: Pointer to first allocation    
 *  - derived: Pointer used with load/store instruction
 * @return ptr  
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_check_bounds(base_ptr: *mut c_void, size: usize) -> bool {
    let base = base_ptr as Vaddr;

    // If not print "Object not found" and return false
    let sobj_table = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");

    // Look up the shadow object corresponding to this access.
    if let Some(sobj) = sobj_table.search_intersection(base) {
        // If shadow object exists then check if the access is within bounds
        if sobj.contains(ShadowObject::limit(base, size)) {
        // Access in Bounds
            return true
        }
    }
    // Access _not_ in Bounds
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let _ = writeln!(&mut writer, "[ERROR] OOB access at 0x{:x}\n", base as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_ERR_LOG_FD, written.as_ptr() as *const _, written.len())};

    false
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_obj_type(base_ptr: *mut c_void) -> AllocType {
    let base = base_ptr as Vaddr;

    let sobj_table = ALIVE_OBJ_LIST.lock().expect("Mutex not poisoned");
    let free_table = FREED_OBJ_LIST.lock().expect("Mutex not poisoned");

    let obj = free_table
        .search_intersection(base)
        .or_else(|| sobj_table.search_intersection(base));
    
    obj.map_or(AllocType::Unknown, |obj| obj.alloc_type)
} 

/**
 * @brief - Logs when program enters a sanitization basic block
 * @input
 *  - ptr: Pointer that is being sanitized
 * @return 
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_report_sanitize_mem_inst_triggered(ptr: *mut c_void) {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let _ = writeln!(&mut writer, "[SANITIZE] Applying sanitizer to address 0x{:x}", ptr as Vaddr);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

/**
 * @brief - Logs when program enters sanitization basic block for arithmetic operations
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_report_sanitizer_triggered() -> () {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let _ = writeln!(&mut writer, "[SANITIZE] Applying arithmetic sanitization in basic block");
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len() )};
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
        let table = ShadowObjectTable::new();
        //table.bounds(0xDEADBEEF).unwrap(); // should panic since there is no interesection

    }
}