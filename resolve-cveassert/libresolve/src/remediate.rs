// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{
    c_char, c_void, calloc, free, malloc, realloc, strdup, strlen, strndup, strnlen,
};

use crate::provenance::{TRACKED_PTRS, Vaddr};
use log::{info, warn};

/**
 * @brief - Allocator interface for stack objects
 * @input - size of the pointer allocation in bytes
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_alloca(ptr: *mut c_void, size: usize) -> () {
    let base = ptr as Vaddr;
    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.add_ptr_metadata(base, size);
    }

    info!("[STACK] Object allocated with size: {size}, address: 0x{base:x}");
}


#[unsafe(no_mangle)]
pub extern "C" fn __resolve_invalidate_stack(base: *mut c_void) {
    let base = base as Vaddr;

    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.invalidate_at(base);
    }

    info!("[STACK] Free addr 0x{base:x}");
}

/**
 * @brief - Allocator logging interface for malloc
 * @input - size of the allocation in bytes
 * @return - ptr to the allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_malloc(size: usize) -> *mut c_void {
    let ptr = unsafe { malloc(size) };
    let base = ptr as Vaddr;

    if ptr.is_null() {
        info!("[ERROR]
        Failed to allocate memory of size: {size}, returning a null pointer
        ");
        return ptr;
    }

    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.add_ptr_metadata(base, size);
    }

    info!(
        "[HEAP] Object allocated with size: {size}, address: 0x{:x}",
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
pub extern "C" fn __resolve_free(ptr: *mut c_void) -> () {
    info!(
        "[FREE] Freed ptr at address: 0x{:x}",
        ptr as Vaddr
    );

        
    {
        let mut ptr_table = TRACKED_PTRS.lock();
        // TODO: Maybe add handling here to handle 'None' case?
        let _ = ptr_table.search_intersection(ptr as Vaddr);
        ptr_table.invalidate_at(ptr as Vaddr);
    }

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
pub extern "C" fn __resolve_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // Edge cases
    // 1. returned memory may not be allocated 
    // 2. pointer passed to realloc may be NULL
    // 3. size fits within original allocation (returns the original ptr)
    
    // Consideration: Pointer passed in may be invalidated so we need a mechanism
    // to remove the shadow object for the orignal allocation
    let realloc_ptr = unsafe { realloc(ptr, size) };
    let base = realloc_ptr as Vaddr;

    if realloc_ptr.is_null() {
        return realloc_ptr;
    }


    {
        let mut ptr_table = TRACKED_PTRS.lock();
        // Remove metadata for original pointer
        ptr_table.invalidate_at(base); // if ptr == NULL this does not do anything 
        ptr_table.add_ptr_metadata(base, size);
    }

    info!(
        "[HEAP] Allocated object reallocated mem from src: {ptr:?}, size: {size}, dst ptr: 0x{:x}",
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
pub extern "C" fn __resolve_calloc(n_items: usize, item_size: usize) -> *mut c_void {
    let ptr = unsafe { calloc(n_items, item_size) };
    let size = n_items * item_size;

    if ptr.is_null() {
        return ptr;
    }

    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.add_ptr_metadata(ptr as Vaddr, size);
    }

    info!(
        "[HEAP] Logging allocation with {n_items} items, size (bytes): {size}, dst ptr: 0x{:x}",
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
pub extern "C" fn __resolve_strdup(ptr: *mut c_char) -> *mut c_char {
    let string_ptr = unsafe { strdup(ptr) };

    if string_ptr.is_null() {
        return string_ptr;
    }

    // +1 to include null termination byte. We should allow program to read this value.
    // Otherwise how would the program find the end of the string?
    // Although writing it to something else is probably a bad idea, this too should be allowed.
    let sizeofstr = unsafe { strlen(ptr) + 1 };
    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.add_ptr_metadata(string_ptr as Vaddr, sizeofstr);
    }

    info!(
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
pub extern "C" fn __resolve_strndup(ptr: *mut c_char, size: usize) -> *mut c_char {
    let string_ptr = unsafe { strndup(ptr, size) };

    if string_ptr.is_null() {
        return string_ptr;
    }

    // +1 to include null termination byte. We should allow program to read this value.
    // We don't actually know how much memory the libc will allocate, but
    // strnlen(ptr, size) + 1 is a safe lower bound.
    // strlen(string_ptr) + 1 would also be valid I think.
    let sizeofstr = unsafe { strnlen(ptr, size) + 1 };

    {
        let mut ptr_table = TRACKED_PTRS.lock();
        ptr_table.add_ptr_metadata(string_ptr as Vaddr, sizeofstr);
    }

    info!(
        "[HEAP] Logging 'strndup' function call with size (bytes): {size}, dst ptr: {:?}",
        string_ptr as Vaddr
    );

    string_ptr
}

#[repr(C)]
pub struct PtrBounds {
    pub base: *mut c_void,
    pub limit: *mut c_void,
}

/**
 * @brief - Helper function that queries metadata table
 *          and returns the metadata that corresponds to
 *          the pointer 
 * @input
 *  - ptr: ptr to allocation 
 * @return metadata containing the base and limit of 
 *  tracked pointer 
 */

// TODO: Rewrite this fn to use the provenance metadata
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_get_bounds(ptr: *mut c_void) -> PtrBounds {
    let ptr_table = TRACKED_PTRS.lock();
    let Some(bounds) = ptr_table.search_intersection(ptr as Vaddr) else {
        return PtrBounds { base: std::ptr::null_mut(), limit: std::ptr::null_mut() }
    };

    return PtrBounds { base: bounds.base as *mut c_void, limit: bounds.limit as *mut c_void }
}

//#[unsafe(no_mangle)]
//pub extern "C" fn resolve_obj_type(base_ptr: *mut c_void) -> AllocType {
//    let base = base_ptr as Vaddr;
//
//    let find_in = |table: &crate::MutexWrap<crate::shadowobjs::ShadowObjectTable>| {
//        let t = table.lock();
//        t.search_intersection(base).map(|o| o.alloc_type)
//    };
//
//    // Why does this search freed before alive?
//    let alloc_type = find_in(&FREED_OBJ_LIST).or_else(|| find_in(&ALIVE_OBJ_LIST));
//
//    alloc_type.unwrap_or(AllocType::Unknown)
//}
//

/**
 * @brief - Logs when program enters sanitization basic block
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_report_violation() -> () {
    info!("[RESOLVE] sanitizer triggered");
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//    use crate::{resolve_init, shadowobjs::AllocType};
//
//    #[test]
//    fn test_malloc_free() {
//        resolve_init();
//        // Allocation should successfully return a memory block
//        let ptr = __resolve_malloc(0x10);
//        assert!(!ptr.is_null());
//
//        // We should track the obj correctly
//        {
//            let table = ALIVE_OBJ_LIST.lock();
//            let obj = table.search_intersection(ptr as Vaddr);
//
//            assert!(obj.is_some());
//            let obj = obj.unwrap();
//            assert!(obj.size() == 0x10);
//            assert!(obj.base == ptr as Vaddr);
//            assert!(obj.alloc_type == AllocType::Heap);
//        }
//
//        __resolve_free(ptr);
//
//        // After freeing a block we should track that it has been freed
//        {
//            let table = FREED_OBJ_LIST.lock();
//            let obj = table.search_intersection(ptr as Vaddr);
//
//            assert!(obj.is_some());
//        }
//
//        // And it should no longer be in the alive obj list.
//        {
//            let table = ALIVE_OBJ_LIST.lock();
//            let obj = table.search_intersection(ptr as Vaddr);
//
//            assert!(obj.is_none());
//        }
//    }
//}
