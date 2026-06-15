// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use libc::{
    c_char, c_int, c_void, calloc, free, malloc, mmap, munmap, off_t, realloc, strdup, strlen,
    strndup, strnlen,
};

use crate::shadowobjs::{
    ALIVE_OBJ_LIST, AllocType, FREED_OBJ_LIST, GLOBALS, SHADOW_STACK, ShadowObject, Vaddr,
    lookup_global,
};

use log::{info, warn};

#[repr(C)]
struct BoundsInfo {
    base: *mut c_void,
    limit: *mut c_void,
    block_size: usize,
    block_index: usize,
}

#[link(name = "mimalloc")]
unsafe extern "C" {
    // Allocator API 
    fn mi_malloc(size: usize) -> *mut c_void;
    fn mi_calloc(size: usize, count: usize) -> *mut c_void;
    fn mi_realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn mi_strdup(ptr: *mut c_char) -> *mut c_char;
    fn mi_strndup(ptr: *mut c_char, size: usize) -> *mut c_char;
    fn mi_free(ptr: *mut c_void);
    fn mi_new(size: usize) -> *mut c_void;
    fn mi_delete(ptr: *mut c_void);
    
    // Shim API
    fn mi_resolve_ptr(ptr: *mut c_void) -> BoundsInfo;
    fn mi_is_heap_owned(ptr: *mut c_void) -> bool;
}

/**
 * @brief - Registers stack allocations in shadow memory
 * @input
 *  - ptr: ptr to stack allocation
 *  - size: size of stack allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_alloca(ptr: *mut c_void, size: usize) -> () {
    let base = ptr as Vaddr;

    SHADOW_STACK.with_borrow_mut(|ss| ss.add_shadow_object(base, size));

    info!(
        "[STACK] Registered stack object: addr={:p}, size={}",
        ptr, size
    );
}

/**
 * @brief - Registers global allocations in shadow memory
 * @input
 *  - ptr: ptr to global allocation
 *  - size: size of global allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_register_global(ptr: *mut c_void, size: usize) {
    GLOBALS
        .lock()
        .push(ShadowObject::new(AllocType::Global, ptr as Vaddr, size));
}

#[unsafe(no_mangle)]
pub extern "C" fn __resolve_invalidate_stack_range(ptr: *mut c_void, size: usize) {
    let base = ptr as Vaddr;

    SHADOW_STACK.with_borrow_mut(|ss| ss.invalidate_at(base, size));

    info!("[STACK] Free addr 0x{base:x} size {size}");
}

#[unsafe(no_mangle)]
pub extern "C" fn __resolve_getline(lineptr: *mut *mut c_char, size: *mut size_t, stream: *mut FILE) -> ssize_t {
    if lineptr.is_null() || size.is_null() || stream.is_null() {
        return -1;
    }

    unsafe {
        if (*lineptr).is_null() || *size == 0 {
            *size = 128;
            *lineptr = __resolve_malloc(*size) as *mut c_char;

            // check if the pointer is null
            if (*lineptr).is_null() { return -1; }
        }

        let mut pos: size_t = 0;
        let mut c: c_int;

        loop {
            c = fgetc(stream);
            if c == EOF { break; }

            if pos + 1 >= *size { // Expand buffer
                let new_size = *size * 2;
                let new_buf = __resolve_realloc(*lineptr as *mut c_void, new_size);

                if new_buf.is_null() {
                    return -1;
                }

                *lineptr = new_buf as *mut c_char;
                *size = new_size;
            }

            // (*lineptr)[pos++] = (char)c;
            (*lineptr).add(pos).write(c as c_char);
            pos += 1;

            if c == b'\n' as c_int {
                break;
            }                                 

        }

        if pos == 0 && c == EOF { // No data read
            return -1;
        }

        (*lineptr).add(pos).write(0); // (*lineptr)[pos] = '\0'
        pos as ssize_t
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __resolve_getdelim(lineptr: *mut *mut c_char, size: *mut size_t, delim: c_int, stream: *mut FILE) -> ssize_t {
    if lineptr.is_null() || size.is_null() || stream.is_null() {
        return -1;
    }

    unsafe {
        if (*lineptr).is_null() || *size == 0 {
            *size = 128;
            *lineptr = __resolve_malloc(*size) as *mut c_char;

            if (*lineptr).is_null() { return -1; }
        }

        let mut pos: size_t = 0;
        let mut c: c_int;

        loop {
            c = fgetc(stream);
            if c == EOF { break; }

            if pos + 1 >= *size {
                let new_size = *size * 2;
                let new_buf = __resolve_realloc(*lineptr as *mut c_void, new_size);

                if new_buf.is_null() { return -1; }
            
                *lineptr = new_buf as *mut c_char;
                *size = new_size;
            }

            (*lineptr).add(pos).write(c as c_char);
            pos += 1;

            if c == delim { break; }
        }

        (*lineptr).add(pos).write(0);
        pos as ssize_t
    }
}

/**
 * @brief - Allocator logging interface for malloc
 * @input - size of the allocation in bytes
 * @return - ptr to the allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_malloc(size: usize) -> *mut c_void {
    let ptr = unsafe { mi_malloc(size + 1) };
    //let bounds_info = unsafe { mi_resolve_ptr(ptr) };

    if ptr.is_null() {
        return ptr;
    }

    //{
    //    let mut obj_list = ALIVE_OBJ_LIST.lock();
    //    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);
    //}

    info!(
        "[HEAP] Registered heap object (malloc): addr={:p}, size={}",
        ptr, size
    );

    //info!("[RESOLVE] bounds: (0x{:x}, 0x{:x})", bounds_info.base as Vaddr, bounds_info.limit as Vaddr);
    //info!("[RESOLVE] block index: {}", bounds_info.block_index);
    //info!("[RESOLVE] block size: {}", bounds_info.block_size);
    ptr
}


#[unsafe(no_mangle)]
pub extern "C" fn __resolve_new(size: usize) -> *mut c_void {
    let ptr = unsafe { mi_new(size + 1) };

    if ptr.is_null() {
        return ptr;
    }

    ptr
}

/**
 * @brief - RESOLVE wrapper for libc free
 * @input
 *  - ptr: ptr to heap allocation
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_free(ptr: *mut c_void) -> () {
    let obj_size = {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        let sobj_opt = obj_list.search_intersection(ptr as Vaddr);
        let size = sobj_opt.map(|o| o.size());
        // remove shadow obj from live list
        obj_list.invalidate_at(ptr as Vaddr);
        size
    };

    // Check if the shadow object exists
    match obj_size {
        Some(size) => {
            info!(
                "[HEAP] Found shadow object for allocated object: 0x{:x}, size = {size}",
                ptr as Vaddr,
            );

<<<<<<< HEAD
            info!(
                "[HEAP] Unregistered heap object: addr={:p}, size={}",
                ptr, size
            );
        }
        None => {
            warn!(
                "[HEAP] No shadow object found for allocated object: 0x{:x}",
                ptr as Vaddr
            );
        }
=======
  // let ptr_size = {
  //     let mut obj_list = ALIVE_OBJ_LIST.lock();
  //     let sobj_opt = obj_list.search_intersection(ptr as Vaddr);
  //     let size = sobj_opt.map(|o| o.size());
  //     // remove shadow obj from live list
  //     obj_list.invalidate_at(ptr as Vaddr);
  //     size
  // };

  // // Check if the shadow object exists
  // match ptr_size {
  //     Some(size) => {
  //         info!(
  //             "[FREE] Found shadow object for allocated object, 0x{:x}, size = {size}",
  //             ptr as Vaddr,
  //         );
  //     }
  //     None => {
  //         warn!(
  //             "[FREE] No shadow object found for allocated object: 0x{:x}",
  //             ptr as Vaddr
  //         );
  //     }
  // }

    {
        // Insert shadow object into freed object list
        let mut freed_guard = FREED_OBJ_LIST.lock();
        freed_guard.add_shadow_object(AllocType::Unallocated, ptr as Vaddr, obj_size.unwrap_or(0));
    }

  let _ = unsafe { mi_free(ptr) };
}
//


#[unsafe(no_mangle)]
pub extern "C" fn __resolve_delete(ptr: *mut c_void) -> () {
    if ptr.is_null() { return; }
    let _ = unsafe { mi_free(ptr) };
}
/**
 * @brief - RESOLVE wrapper for libc realloc
 * @input
 *  - ptr: ptr to heap allocation
 *  - size: size of requested reallocation in bytes
 * @return a new pointer pointing the new object of the
 *         requested size
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // Edge cases
    // 1. returned memory may not be allocated
    // 2. pointer passed to realloc may be NULL
    // 3. size fits within original allocation (returns the original ptr)

    // Consideration: Pointer passed in may be invalidated so we need a mechanism
    // to remove the shadow object for the orignal allocation
    let realloc_ptr = unsafe { mi_realloc(ptr, size + 1) };

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
        "[HEAP] Registered heap object (realloc): addr={:p}, size={}",
        realloc_ptr, size
    );

   realloc_ptr
}

/**
 * @brief - RESOLVE wrapper for libc calloc
 * @input
 *  - nelems: requested num of elements
 *  - elsize: size of elements in bytes
 * @return a new pointer pointing the new object of the
 *         requested size
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_calloc(n_items: usize, item_size: usize) -> *mut c_void {
    let ptr = unsafe { mi_calloc(n_items, item_size) };
    let size = n_items * item_size;

    if ptr.is_null() {
        return ptr;
    }

    //{
    //    let mut obj_list = ALIVE_OBJ_LIST.lock();
    //    obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, size);
    //}

    info!(
        "[HEAP] Registered heap object (calloc): addr={:p}, size={}",
        ptr, size
    );

    ptr
}

/**
 * @brief - RESOLVE wrapper for libc strdup
 * @input
 *  - ptr: ptr to heap allocation
 * @return a new pointer pointing the new object of the
 *         copied string
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_strdup(ptr: *mut c_char) -> *mut c_char {
    let string_ptr = unsafe { mi_strdup(ptr) };

    if string_ptr.is_null() {
        return string_ptr;
    }

    // +1 to include null termination byte. We should allow program to read this value.
    // Otherwise how would the program find the end of the string?
    // Although writing it to something else is probably a bad idea, this too should be allowed.
   // let sizeofstr = unsafe { strlen(ptr) + 1 };
   // {
   //     let mut obj_list = ALIVE_OBJ_LIST.lock();
   //     obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);
   // }

    info!(
        "[HEAP] Registered heap object (strdup): addr={:p}, size={}",
        string_ptr, sizeofstr
    );

    string_ptr
}

/**
 * @brief - RESOLVE wrapper for libc strndup
 * @input
 *  - ptr: ptr to heap allocation
 *  - size: number of bytes to be copied
 * @return a new pointer pointing a new object of 'size' copied bytes
 * NOTE: Read this link to understand the nature of strdup & strndup
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/strdup.html
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_strndup(ptr: *mut c_char, size: usize) -> *mut c_char {
    let string_ptr = unsafe { mi_strndup(ptr, size + 1) };

    if string_ptr.is_null() {
        return string_ptr;
    }

    // +1 to include null termination byte. We should allow program to read this value.
    // We don't actually know how much memory the libc will allocate, but
    // strnlen(ptr, size) + 1 is a safe lower bound.
    // strlen(string_ptr) + 1 would also be valid I think.
    //let sizeofstr = unsafe { strnlen(ptr, size) + 1 };

    //{
    //    let mut obj_list = ALIVE_OBJ_LIST.lock();
    //    obj_list.add_shadow_object(AllocType::Heap, string_ptr as Vaddr, sizeofstr);
    //}

    info!(
        "[HEAP] Registered heap object (strndup): addr={:p}, size={}",
        string_ptr, sizeofstr
    );

//     string_ptr
// }

/**
 * @brief - RESOLVE wrapper for libc mmap
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    // NOTE: If addr is null then the kernel chooses the (page-aligned) address to create a new
    // mapping.
    let ptr = unsafe { mmap(addr, length + 1, prot, flags, fd, offset) };

    {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        obj_list.add_shadow_object(AllocType::Heap, ptr as Vaddr, length);
    }

    info!(
        "[HEAP] Registered heap object (mmap): addr={:p}, size={}",
        ptr, length
    );

    ptr
}

/**
 * @brief - RESOLVE wrapper for libc munmap
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_munmap(addr: *mut c_void, length: usize) -> c_int {
    let obj_size = {
        let mut obj_list = ALIVE_OBJ_LIST.lock();
        let sobj_opt = obj_list.search_intersection(addr as Vaddr);
        let size = sobj_opt.map(|o| o.size());
        // remove shadow obj from live list
        obj_list.invalidate_at(addr as Vaddr);
        size
    };

    // Check if the shadow object exists
    match obj_size {
        Some(size) => {
            info!(
                "[HEAP] Found shadow object for allocated object: addr={:p}, size={}",
                addr, size
            );

            info!(
                "[HEAP] Unregistered heap object: addr{:p}, size={}",
                addr, size
            );
        }
        None => {
            warn!(
                "[HEAP] No shadow object found for allocated object: addr={:p}",
                addr
            );
        }
    }

    {
        let mut freed_guard = FREED_OBJ_LIST.lock();
        freed_guard.add_shadow_object(AllocType::Unallocated, addr as Vaddr, obj_size.unwrap_or(0));
    }

    let freed = unsafe { munmap(addr, length) };
    freed
}

#[derive(PartialEq)]
#[repr(C)]
pub struct ShadowObjBounds {
    pub base: *mut c_void,
    pub limit: *mut c_void,
}

impl ShadowObjBounds {
    pub fn null() -> Self {
        ShadowObjBounds {
            base: std::ptr::null_mut(),
            limit: std::ptr::null_mut(),
        }
    }
}

impl From<&crate::shadowobjs::ShadowObject> for ShadowObjBounds {
    fn from(sobj: &crate::shadowobjs::ShadowObject) -> Self {
        ShadowObjBounds {
            base: sobj.base as *mut c_void,
            limit: sobj.limit as *mut c_void,
        }
    }
}

/**
 * @brief - Helper function that queries the shadow stack
 *          to find a shadow obj where the ptr fits within
 *          its bounds of allocation
 * @input
 *  - ptr: ptr to allocation
 * @return struct containing the base and limit of the
 *         shadow object as pointers
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_get_bounds_stack(ptr: *mut c_void) -> ShadowObjBounds {
    return SHADOW_STACK.with_borrow(|ss| {
        return match ss.search_intersection(ptr as Vaddr) {
            Some(sobj) => sobj.into(),
            None => ShadowObjBounds::null(),
        };
    });
}

/**
 * @brief - Helper function that queries heap sobj list
 *          to find a shadow obj where the ptr fits within
 *          its bounds of allocation
 * @input
 *  - ptr: ptr to allocation
 * @return struct containing the base and limit of the
 *         shadow object as pointers
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_get_bounds_heap(ptr: *mut c_void) -> ShadowObjBounds {
    let sobj_table = ALIVE_OBJ_LIST.lock();
    let Some(sobj) = sobj_table.search_intersection(ptr as Vaddr) else {
        return ShadowObjBounds::null();
    };

    return sobj.into();
}

/**
 * @brief - Queries recorded globals to find a shadow obj
 *          where the ptr is within bounds of allocation
 * @input
 *  - ptr: ptr to global allocation
 * @return shadow object that satisfies base <= ptr && ptr < limit
 * If shadow object cannot be found the function returns
 * a shadow object with null base and limit pointers
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_get_bounds_global(ptr: *mut c_void) -> ShadowObjBounds {
    match lookup_global(ptr as Vaddr) {
        Some(obj) => (&obj).into(),
        None => ShadowObjBounds::null(),
    }
}

/**
 * @brief - Generic shadow object lookup where we don't know the pointers
 *          allocation type already. Searches stack table ( O(log n) )
 *          before searching the heap table
 * @input
 *  - ptr: ptr to allocation
 * @return struct containing the base and limit of the
 *         shadow object as pointers
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_get_bounds(ptr: *mut c_void) -> ShadowObjBounds {
    let mut sobj = __resolve_get_bounds_stack(ptr);
    if sobj == ShadowObjBounds::null() {
        sobj = __resolve_get_bounds_heap(ptr)
    }
    if sobj == ShadowObjBounds::null() {
        sobj = __resolve_get_bounds_global(ptr)
    }

    sobj
}
//
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

/**
 * @brief - Logs invalid memory access for a given function
 * @input
 *  - ptr: ptr to allocation
 *  - access_size: requested access size
 *  - function: ptr to function name (string literal)
 */
#[unsafe(no_mangle)]
pub extern "C" fn __resolve_report_violation(
    ptr: *mut c_void,
    access_size: usize,
    function: *mut c_char,
) {
    let function = unsafe { CStr::from_ptr(function).to_string_lossy() };

    let bounds = __resolve_get_bounds(ptr);

    info!(
        "[RESOLVE] out-of-bounds error detected!\n\taddress = {:p}\n\tsize = {}\n\tbounds = [{:p}\n\t{:p})\n\tfunction = {}",
        ptr, access_size, bounds.base, bounds.limit, function
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::resolve_init;
    use crate::shadowobjs::AllocType;

   #[test]
   fn test_malloc_free() {
       resolve_init();
       // Allocation should successfully return a memory block
       let ptr = __resolve_malloc(0x10);
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

       __resolve_free(ptr);

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
