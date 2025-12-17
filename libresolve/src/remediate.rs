// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{
    c_char, c_void, calloc, free, malloc, memcpy, realloc, strdup, strlen, strndup, strnlen,
};
use std::io::Write;

use crate::{
    RESOLVE_LOG_FILE,
    shadowobjs::{ALIVE_OBJ_LIST, AllocType, FREED_OBJ_LIST, ShadowObject, Vaddr},
};

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
    let base = ptr as Vaddr;
    let mut obj_list = ALIVE_OBJ_LIST.lock();
    obj_list.add_shadow_object(AllocType::Stack, base, size);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[STACK] Object allocated with size: {}, address: 0x{:x}",
        size,
        base
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_invalidate_stack(base: *mut c_void, limit: *mut c_void) {
    let base = base as Vaddr;
    let limit = limit as Vaddr;
    let mut obj_list = ALIVE_OBJ_LIST.lock();
    // TODO: Add these to a free list?
    obj_list.invalidate_region(base, limit);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[STACK] Free range 0x{base:x}..=0x{limit:x}",
    );
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
        return ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Object allocated with size: {}, address: 0x{:x}",
        size,
        ptr as Vaddr
    );

    // Return the pointer
    ptr
}

/**
 * @brief - Function call to replace llvm 'gep' instruction
 * @input
 *  - ptr: unique pointer root
 *  - derived: pointer derived from unique root ptr
 * @return valid pointer within bounds of allocation or
 * pointer 1-past limit of allocation
 */

#[unsafe(no_mangle)]
pub extern "C" fn resolve_gep(ptr: *mut c_void, derived: *mut c_void) -> *mut c_void {
    let base = ptr as Vaddr;
    let derived = derived as Vaddr;

    let sobj_table = ALIVE_OBJ_LIST.lock();

    // Look up the shadow object corresponding to this access.
    // NOTE: Return 0 ('null') if shadow object cannot be found.
    let Some(sobj) = sobj_table.search_intersection(base) else {
        let _ = writeln!(
            &mut RESOLVE_LOG_FILE.lock(),
            "[GEP] Cannot find ptr 0x{:x} in shadow table",
            base
        );

        // NOTE: Not doing this right now
        // In theory it could catch bugs where integers are forced to pointers...
        // But there are too many allocation we don't know about, like those in libc
        // or the argv pointer.
        // return 0 as *mut c_void;

        // Assume unknown pointers are safe
        return derived as *mut c_void;
    };

    // If shadow object exists then check if the access is within bounds
    if sobj.contains(derived as Vaddr) {
        let _ = writeln!(
            &mut RESOLVE_LOG_FILE.lock(),
            "[GEP] ptr 0x{:x} valid for base 0x{:x}, obj: {}@0x{:x}",
            derived,
            base,
            sobj.size(),
            sobj.base
        );
        return derived as *mut c_void;
    }

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[GEP] ptr 0x{:x} not valid for base 0x{:x}, obj: {}@0x{:x}",
        derived,
        base,
        sobj.size(),
        sobj.base
    );

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
        return ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Object copied to dst: {:?}, from src {:?}, with size: {}, ptr: 0x{:x}",
        dest,
        src,
        size,
        ptr as Vaddr
    );

    ptr
}

/**
 * @brief - Allocator logging interface for free
 * @input - ptr to the allocation
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_free(ptr: *mut c_void) -> () {
    let mut obj_list = ALIVE_OBJ_LIST.lock();

    // Insert a function to find the object and return the pointer size
    // Do I need to handle if the sobj cannot be found?

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[FREE] Allocated object freed at address: 0x{:x}",
        ptr as Vaddr
    );

    // Lookup shadow object
    let sobj_opt = obj_list.search_intersection(ptr as Vaddr);
    let ptr_size: usize;

    // Check if the shadow object exists
    match sobj_opt {
        Some(sobj) => {
            ptr_size = sobj.limit;

            let _ = writeln!(
                &mut RESOLVE_LOG_FILE.lock(),
                "[INFO] Found shadow object for allocated object, 0x{:x}, size = {}",
                ptr as Vaddr,
                ptr_size
            );
        }
        None => {
            ptr_size = 0;
            let _ = writeln!(
                &mut RESOLVE_LOG_FILE.lock(),
                "[WARNING] No shadow object found for allocated object: 0x{:x}",
                ptr as Vaddr
            );
        }
    }

    // remove shadow obj from live list
    obj_list.invalidate_at(ptr as Vaddr);

    // release lock before taking another lock
    drop(obj_list);

    // TODO: Remove object from alive list?
    // Insert shadow object into freed object list
    let mut freed_guard = FREED_OBJ_LIST.lock();
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
        return realloc_ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();
    obj_list.add_shadow_object(AllocType::Heap, realloc_ptr as Vaddr, size);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Allocated object reallocated mem from src: {:?}, size: {}, dst ptr: 0x{:x}",
        ptr,
        size,
        realloc_ptr as Vaddr
    );

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
pub extern "C" fn resolve_calloc(n_items: usize, item_size: usize) -> *mut c_void {
    let ptr = unsafe { calloc(n_items, item_size) };
    let size = n_items * item_size;

    if ptr.is_null() {
        return ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();
    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Logging allocation with {} items, size (bytes): {}, dst ptr: 0x{:x}",
        n_items,
        size,
        ptr as Vaddr
    );

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
        return string_ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();

    // +1 to include null termination byte. We should allow program to read this value.
    // Otherwise how would the program find the end of the string?
    // Although writing it to something else is probably a bad idea, this too should be allowed.
    let sizeofstr = unsafe { strlen(ptr) + 1 };
    obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Logging 'strdup' function call with dst ptr: 0x{:x}",
        string_ptr as Vaddr
    );

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
        return string_ptr;
    }

    let mut obj_list = ALIVE_OBJ_LIST.lock();

    // +1 to include null termination byte. We should allow program to read this value.
    // We don't actually know how much memory the libc will allocate, but
    // strnlen(ptr, size) + 1 is a safe lower bound.
    // strlen(string_ptr) + 1 would also be valid I think.
    let sizeofstr = unsafe { strnlen(ptr, size) + 1 };
    obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[HEAP] Logging 'strndup' function call with size (bytes): {}, dst ptr: {:?}",
        size,
        string_ptr as Vaddr
    );

    string_ptr
}

/**
 * @brief - Returns true if pointer access is within bounds of a known allocation  
 * @input
 *  - base_ptr: address to be dereferenced    
 *  - size: size of dereference in bytes
 * @return true if base_ptr..size is totally within a valid shadow object  
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_check_bounds(base_ptr: *mut c_void, size: usize) -> bool {
    let base = base_ptr as Vaddr;

    let sobj_table = ALIVE_OBJ_LIST.lock();

    // Look up the shadow object corresponding to this access
    if let Some(sobj) = sobj_table.search_intersection(base) {
        // If shadow object exists then check if the access is within bounds
        if sobj.contains(ShadowObject::limit(base, size)) {
            // Access in Bounds
            let _ = writeln!(
                &mut RESOLVE_LOG_FILE.lock(),
                "[BOUNDS] Access allowed {}@0x{:x} for allocation {}@0x{:x}",
                size,
                base,
                sobj.size(),
                sobj.base
            );
            return true;
        } else {
            let _ = writeln!(
                &mut RESOLVE_LOG_FILE.lock(),
                "[ERROR] OOB access at {}@0x{:x} too big for allocation {}@0x{:x}",
                size,
                base,
                sobj.size(),
                sobj.base
            );
            return false;
        }
    }

    // Check if this is an invalid pointer for one of the known shadow objects
    if let Some(sobj) = sobj_table.search_invalid(base) {
        let _ = writeln!(
            &mut RESOLVE_LOG_FILE.lock(),
            "[ERROR] OOB access for {}@0x{:x}, invalid address computation",
            sobj.size(),
            sobj.base
        );
        return false;
    }

    // Not a tracked pointer, assume good to avoid false positives
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_obj_type(base_ptr: *mut c_void) -> AllocType {
    let base = base_ptr as Vaddr;

    let sobj_table = ALIVE_OBJ_LIST.lock();
    let free_table = FREED_OBJ_LIST.lock();

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
    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[SANITIZE] Applying sanitizer to address 0x{:x}",
        ptr as Vaddr
    );
}

/**
 * @brief - Logs when program enters sanitization basic block for arithmetic operations
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_report_sanitizer_triggered() -> () {
    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[SANITIZE] Applying arithmetic sanitization in basic block"
    );
}
