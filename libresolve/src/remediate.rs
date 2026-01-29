// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{
    c_char, c_void, calloc, free, malloc, realloc, strdup, strlen, strndup, strnlen,
};

use crate::shadowobjs::{ALIVE_OBJ_LIST, AllocType, FREED_OBJ_LIST, Vaddr};

use log::{info, warn};

/**
 * @brief - Allocator interface for stack objects
 * @input - size of the pointer allocation in bytes
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_stack_obj(ptr: *mut c_void, size: usize) -> () {
    let base = ptr as Vaddr;
    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Stack, base, size);
    }

    info!("[STACK] Object allocated with size: {size}, address: 0x{base:x}");
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_invalidate_stack(base: *mut c_void) {
    let base = base as Vaddr;

    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.invalidate_at(base);
    }

    info!("[STACK] Free addr 0x{base:x}");
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

    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);
    }

    info!(
        "[HEAP] Object allocated with size: {size}, address: 0x{:x}",
        ptr as Vaddr
    );

    // Return the pointer
    ptr
}

/**
 * @brief - Allocator logging interface for free
 * @input - ptr to the allocation
 * @return - none
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_free(ptr: *mut c_void) -> () {
    // Insert a function to find the object and return the pointer size
    // Do I need to handle if the sobj cannot be found?

    info!(
        "[FREE] Allocated object freed at address: 0x{:x}",
        ptr as Vaddr
    );

    let ptr_size = {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        // Lookup shadow object
        let sobj_opt = obj_list.search_intersection(ptr as Vaddr);
        let size = sobj_opt.map(|o| o.size());
        // remove shadow obj from live list
        obj_list.invalidate_at(ptr as Vaddr);
        size
    };

    // Check if the shadow object exists
    match ptr_size {
        Some(size) => {
            info!(
                "[FREE] Found shadow object for allocated object, 0x{:x}, size = {size}",
                ptr as Vaddr,
            );
        }
        None => {
            warn!(
                "[FREE] No shadow object found for allocated object: 0x{:x}",
                ptr as Vaddr
            );
        }
    }

    {
        // Insert shadow object into freed object list
        let mut freed_guard = FREED_OBJ_LIST.lock();
        freed_guard.add_shadow_object(AllocType::Unallocated, ptr as Vaddr, ptr_size.unwrap_or(0));
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
pub extern "C" fn resolve_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // Edge cases
    // 1. returned memory may not be allocated 
    // 2. pointer passed to realloc may be NULL
    // 3. size fits within original allocation (returns the original ptr)
    
    // Consideration: Pointer passed in may be invalidated so we need a mechanism
    // to remove the shadow object for the orignal allocation
    let realloc_ptr = unsafe { realloc(ptr, size + 1) };

    if realloc_ptr.is_null() {
        return realloc_ptr;
    }


    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        // Remove shadow object for original pointer
        obj_list.invalidate_at(ptr as Vaddr); // if ptr == NULL this does not do anything 
        obj_list.add_shadow_object(AllocType::Heap, realloc_ptr as Vaddr, size);
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
pub extern "C" fn resolve_calloc(n_items: usize, item_size: usize) -> *mut c_void {
    let ptr = unsafe { calloc(n_items, item_size) };
    let size = n_items * item_size;

    if ptr.is_null() {
        return ptr;
    }

    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);
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
pub extern "C" fn resolve_strdup(ptr: *mut c_char) -> *mut c_char {
    let string_ptr = unsafe { strdup(ptr) };

    if string_ptr.is_null() {
        return string_ptr;
    }

    // +1 to include null termination byte. We should allow program to read this value.
    // Otherwise how would the program find the end of the string?
    // Although writing it to something else is probably a bad idea, this too should be allowed.
    let sizeofstr = unsafe { strlen(ptr) + 1 };
    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);
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
pub extern "C" fn resolve_strndup(ptr: *mut c_char, size: usize) -> *mut c_char {
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
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);
    }

    info!(
        "[HEAP] Logging 'strndup' function call with size (bytes): {size}, dst ptr: {:?}",
        string_ptr as Vaddr
    );

    string_ptr
}

#[repr(C)]
pub struct ShadowObjBounds {
    pub base: *mut c_void,
    pub limit: *mut c_void,
}

/**
 * @brief - Helper function that queries shadow obj list
 *          to find a shadow obj where the ptr fits within
 *          its bounds of allocation 
 * @input
 *  - ptr: ptr to allocation 
 * @return struct containing the base and limit of the
 *         shadow object as pointers 
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_get_base_and_limit(ptr: *mut c_void) -> ShadowObjBounds {
    let sobj_table = ALIVE_OBJ_LIST.lock();
    let Some(sobj) = sobj_table.search_intersection(ptr as Vaddr) else {
        return ShadowObjBounds { base: std::ptr::null_mut(), limit: std::ptr::null_mut() }
    };

    return ShadowObjBounds { base: sobj.base as *mut c_void, limit: sobj.limit as *mut c_void }
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_obj_type(base_ptr: *mut c_void) -> AllocType {
    let base = base_ptr as Vaddr;

    let find_in = |table: &crate::MutexWrap<crate::shadowobjs::ShadowObjectTable>| {
        let t = table.lock();
        t.search_intersection(base).map(|o| o.alloc_type)
    };

    // Why does this search freed before alive?
    let alloc_type = find_in(&FREED_OBJ_LIST).or_else(|| find_in(&ALIVE_OBJ_LIST));

    alloc_type.unwrap_or(AllocType::Unknown)
}

/**
 * @brief - Logs when program enters a sanitization basic block
 * @input
 *  - ptr: Pointer that is being sanitized
 * @return
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_report_sanitize_mem_inst_triggered(ptr: *mut c_void) {
    info!(
        "[SANITIZE] Applying sanitizer to address 0x{:x}",
        ptr as Vaddr
    );
}

/**
 * @brief - Logs when program enters sanitization basic block for arithmetic operations
 */
#[unsafe(no_mangle)]
pub extern "C" fn resolve_report_sanitizer_triggered() -> () {
    info!("[SANITIZE] Applying arithmetic sanitization in basic block");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resolve_init, shadowobjs::AllocType};

    #[test]
    fn test_malloc_free() {
        resolve_init();
        // Allocation should successfully return a memory block
        let ptr = resolve_malloc(0x10);
        assert!(!ptr.is_null());

        // We should track the obj correctly
        {
            let table = ALIVE_OBJ_LIST.lock();
            let obj = table.search_intersection(ptr as Vaddr);

            assert!(obj.is_some());
            let obj = obj.unwrap();
            assert!(obj.size() == 0x10);
            assert!(obj.base == ptr as Vaddr);
            assert!(obj.alloc_type == AllocType::Heap);
        }

        resolve_free(ptr);

        // After freeing a block we should track that it has been freed
        {
            let table = FREED_OBJ_LIST.lock();
            let obj = table.search_intersection(ptr as Vaddr);

            assert!(obj.is_some());
        }

        // And it should no longer be in the alive obj list.
        {
            let table = ALIVE_OBJ_LIST.lock();
            let obj = table.search_intersection(ptr as Vaddr);

            assert!(obj.is_none());
        }
    }
}
