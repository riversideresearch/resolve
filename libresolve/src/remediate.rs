// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{
    c_char, c_void, calloc, free, malloc, realloc, strdup, strlen, strndup, strnlen,
};

use crate::shadowobjs::{
    ALIVE_OBJ_LIST, AllocType, FREED_OBJ_LIST, STACK_OBJ_LIST, ShadowObject, Vaddr,
};

use log::{error, info, trace, warn};

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

    STACK_OBJ_LIST.with_borrow_mut(|l| {
        l.add_shadow_object(AllocType::Stack, base, size);
    });

    info!("[STACK] Object allocated with size: {size}, address: 0x{base:x}");
}

/*
#[unsafe(no_mangle)]
pub extern "C" fn resolve_invalidate_stack(base: *mut c_void) {
pub extern "C" fn resolve_invalidate_stack(base: *mut c_void) {
    let base = base as Vaddr;

    STACK_OBJ_LIST.with_borrow_mut(|l| {
        l.invalidate_at(base);
    });

    info!("[STACK] Free range 0x{base:x}");
}
*/

macro_rules! invalidate_stacks {
    ($name:ident; $($ns:literal),+) => {

#[unsafe(no_mangle)]
pub extern "C" fn $name($(${concat(base_, $ns)}: *mut c_void, )+) {

    STACK_OBJ_LIST.with_borrow_mut(|l| {
        $(
        l.invalidate_at(${concat(base_, $ns)} as Vaddr);
        info!("[STACK] Free address 0x{:x}", ${concat(base_, $ns)} as Vaddr);
        )+
    });

}

    }
}

// the x64 ABI allows up to 6 arguments to be passed via register,
// so provide that many functions as we cannot define a variadic
invalidate_stacks!(resolve_invalidate_stack; 1);
invalidate_stacks!(resolve_invalidate_stack_2; 1, 2);
invalidate_stacks!(resolve_invalidate_stack_3; 1, 2, 3);
invalidate_stacks!(resolve_invalidate_stack_4; 1, 2, 3, 4);
invalidate_stacks!(resolve_invalidate_stack_5; 1, 2, 3, 4, 5);
invalidate_stacks!(resolve_invalidate_stack_6; 1, 2, 3, 4, 5, 6);

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
 * @brief - Function call to replace llvm 'gep' instruction
 * @input
 *  - ptr: unique pointer root
 *  - derived: pointer derived from unique root ptr
 * @return valid pointer within bounds of allocation or
 * pointer 1-past limit of allocation
 */

#[unsafe(no_mangle)]
pub extern "C" fn resolve_gep(ptr: *mut c_void, derived: *mut c_void, max_access: usize) -> *mut c_void {
    let base = ptr as Vaddr;
    let derived = derived as Vaddr;

    
    let contains_or_err = |obj: &ShadowObject| {
        // If shadow object exists then check if the access is within bounds
        if obj.contains(ShadowObject::limit(derived, max_access)) {
            trace!(
                "[GEP] ptr {max_access}x{derived:x} valid for base 0x{base:x}, obj: {}@0x{:x}",
                obj.size(),
                obj.base
            );
            return derived as *mut c_void;
        }

        error!(
            "[GEP] ptr {max_access}x{derived:x} not valid for base 0x{base:x}, obj: {}@0x{:x}",
            obj.size(),
            obj.base
        );

        // Pointer known-invalid, return sentinel to indicate failure
        0 as *mut c_void
    };

    // Check the local stack list first since it is cheaper.
    if let Some(sobj) = STACK_OBJ_LIST.with_borrow(|l| l.search_intersection(base).cloned()) {
        return contains_or_err(&sobj);
    };

    let sobj_table = ALIVE_OBJ_LIST.lock();

    // Look up the shadow object corresponding to this access.
    let Some(sobj) = sobj_table.search_intersection(base) else {
        warn!("[GEP] Cannot find ptr 0x{base:x} in shadow table");

        // NOTE: Not doing this right now
        // In theory it could catch bugs where integers are forced to pointers...
        // But there are too many allocation we don't know about, like those in libc
        // or the argv pointer.
        // return 0 as *mut c_void;

        // Assume unknown pointers are safe
        return derived as *mut c_void;
    };

    contains_or_err(sobj)
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

    // Nullptr clearly are not valid, and may be returned by resolve_gep if it is an invalid call.
    if base == 0 {
        return false;
    }

    let contains_or_err = |obj: &ShadowObject| {
        // If shadow object exists then check if the access is within bounds
        if obj.contains(ShadowObject::limit(base, size)) {
            // Access in Bounds
            trace!(
                "[BOUNDS] Access allowed {size}@0x{base:x} for allocation {}@0x{:x}",
                obj.size(),
                obj.base
            );
            return true;
        } else {
            error!(
                "[BOUNDS] OOB access at {size}@0x{base:x} too big for allocation {}@0x{:x}",
                obj.size(),
                obj.base
            );
            return false;
        }
    };

    if let Some(sobj) = STACK_OBJ_LIST.with_borrow(|l| l.search_intersection(base).cloned()) {
        return contains_or_err(&sobj);
    }

    // Look up the shadow object corresponding to this access
    let sobj_table = ALIVE_OBJ_LIST.lock();
    if let Some(sobj) = sobj_table.search_intersection(base) {
        return contains_or_err(sobj);
    }

    // Check if this is an invalid pointer for one of the known shadow objects
    if let Some(sobj) = sobj_table.search_invalid(base) {
        error!(
            "[BOUNDS] OOB access for {}@0x{:x}, invalid address computation",
            sobj.size(),
            sobj.base
        );
        return false;
    }

    warn!("[BOUNDS] unknown pointer 0x:{base:x}");

    // Not a tracked pointer, assume good to avoid trapping on otherwise valid pointers
    // TODO: add a strict mode to reject here / add extra tracking.
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve_obj_type(base_ptr: *mut c_void) -> AllocType {
    let base = base_ptr as Vaddr;

    let find_in = |table: &crate::shadowobjs::ShadowObjectTable| {
        table.search_intersection(base).map(|o| o.alloc_type)
    };

    // Why does this search freed before alive?
    let alloc_type = STACK_OBJ_LIST
        .with_borrow(|l| find_in(l))
        .or_else(|| {
            let l = FREED_OBJ_LIST.lock();
            find_in(&l)
        })
        .or_else(|| {
            let l = ALIVE_OBJ_LIST.lock();
            find_in(&l)
        });

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
    error!(
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
    use test::Bencher;

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

    #[test]
    fn test_resolve_check_bounds() {
        resolve_init();
        // Spray the heap a little
        let ptrs: Vec<_> = (0x01..0x100).map(|i| resolve_malloc(i)).collect();

        //let mut rng = rand::rng();

        for (i, p) in ptrs.into_iter().enumerate() {
            let i = i + 1;
            assert!(!p.is_null());

            // Check all valid bounds
            for offset in 0..i {
                // the size/offset must be greater than 0
                assert!(
                    resolve_check_bounds(p, offset + 1),
                    "{:x}, {:x}",
                    p as usize,
                    offset + 1
                );
                for j in offset..i {
                    assert!(resolve_check_bounds(
                        unsafe { p.offset(offset as isize) },
                        i - j
                    ));
                }
            }

            // out of bounds accesses
            // before first
            // Current code allows this because we allow pointers we haven't tracked
            // assert!(!resolve_check_bounds(unsafe { p.offset(-1) }, 1));
            // after last
            assert!(!resolve_check_bounds(unsafe { p.offset(i as isize) }, 1));
            assert!(!resolve_check_bounds(p, i + 1));

            // In theory all pointer arithmetic instructions translate into GetElementPtr
            // instructions in llvm-ir which will verify that the base/derived pointers are valid
            // and within the correct allocations.

            resolve_free(p);
        }
    }

    
    #[bench]
    fn bench_resolve_stack(b: &mut Bencher) {
        resolve_init();

        let addrs: Vec<_> = (0x7FFF_0000_0000_0000..0x7FFF_0000_0001_0000)
            .map(|a: usize| a as *mut c_void)
            .collect();

        b.iter(|| {
            addrs.iter().for_each(|a| resolve_stack_obj(*a, 1));

            addrs.iter().for_each(|&a| {
                let _ = resolve_gep(a, a, 1);
            });

            addrs.iter().for_each(|a| resolve_invalidate_stack(*a));
        });
    }
}
