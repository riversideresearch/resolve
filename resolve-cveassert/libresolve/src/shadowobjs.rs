// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use crate::MutexWrap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::ops::Bound::Included;

/// An alias representing Virtual Address values
pub type Vaddr = usize;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AllocType {
    Unallocated,
    Unknown,
    Heap,
    Stack,
    #[allow(dead_code)]
    Global,
}

#[derive(Debug, Clone)]
pub struct ShadowObject {
    /// Allocation type (Heap, Stack, Global, etc..)
    pub alloc_type: AllocType,
    // Base address of the allocated object mapped to u64
    pub base: Vaddr,
    /// Last address of the allocated object
    pub limit: Vaddr,
    size: usize,
}

impl ShadowObject {
    /// Returns the base + limit of this shadow object as RangeInclusive
    ///
    /// Useful for querying contains
    pub fn bounds(&self) -> RangeInclusive<Vaddr> {
        self.base..=self.limit
    }

    /// Test if `addr` is within the bounds of this shadow object
    pub fn contains(&self, addr: Vaddr) -> bool {
        self.bounds().contains(&addr)
    }

    // pub fn contains_region(&self, base: Vaddr, limit: Vaddr) -> bool {
    //     self.contains(base) && self.contains(limit)
    // }

    /// Computes the size of the shadow object from its base and limit
    pub fn size(&self) -> usize {
        self.size
    }

    /// Compute a limit from base and size
    pub fn limit(base: Vaddr, size: usize) -> Vaddr {
        if size == 0 { base } else { base + size - 1 }
    }

    /// Compute the sentinel pointer value for this object, 1 past its limit
    pub fn past_limit(&self) -> Vaddr {
        self.limit + 1
    }
}

pub struct ShadowObjectTable {
    table: BTreeMap<Vaddr, ShadowObject>,
}

impl ShadowObjectTable {
    pub const fn new() -> ShadowObjectTable {
        ShadowObjectTable {
            table: BTreeMap::new(),
        }
    }

    /// Adds a new shadow object to the object list, replacing any existing object at `base`
    pub fn add_shadow_object(&mut self, alloc_type: AllocType, base: Vaddr, size: usize) {
        let sobj = ShadowObject {
            alloc_type,
            base,
            limit: ShadowObject::limit(base, size),
            size,
        };
        self.table.insert(base, sobj);
    }

    /// Removes the shadow object with base address equal to `base`.
    ///
    /// Does nothing if there is no shadow object at that address.
    pub fn invalidate_at(&mut self, base: Vaddr) {
        let _ = self.table.remove(&base);
    }

    /// Removes any allocation with a base address within the supplied region
    #[allow(dead_code)]
    pub fn invalidate_region(&mut self, base: Vaddr, limit: Vaddr) {
        self.table
            .extract_if(base..=limit, |_, _| true)
            .for_each(|_| {})
    }

    /// Finds a shadow object that contains 'addr' in its bounds OR a shadow object with
    /// a past_limit value matching the input
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {
        let cursor = self.table
            .upper_bound(Included(&addr));

        cursor.peek_prev()
            .filter(|(_, o)| o.contains(addr) || o.past_limit() == addr)
            .map(|(_, o)| o) 
    }  
}

// static object lists to store all objects
pub static ALIVE_OBJ_LIST: MutexWrap<ShadowObjectTable> = MutexWrap::new(ShadowObjectTable::new());
pub static FREED_OBJ_LIST: MutexWrap<ShadowObjectTable> = MutexWrap::new(ShadowObjectTable::new());

enum ShadowStackValue {
    ShadowObject(ShadowObject),
    InvalidatedObject(Vaddr,usize)
}

impl ShadowStackValue {
    fn base(&self) -> Vaddr {
        match self {
            ShadowStackValue::ShadowObject(o) => o.base,
            ShadowStackValue::InvalidatedObject(b, _s) => *b,
        }
    }

    fn size(&self) -> usize {
        match self {
            ShadowStackValue::ShadowObject(o) => o.size,
            ShadowStackValue::InvalidatedObject(_b, s) => *s,
        }
    }

    fn contains(&self, addr: Vaddr) -> bool {
        let base = self.base();

        let Some(end) = base.checked_add(self.size() as Vaddr) else {
            return false;
        };

        base <= addr && addr < end
    }
}

// data must be ordered descending (downward growing stack on x86)
// so push/pop are O(1) at the end.
#[derive(Default)]
pub struct ShadowStack {
    data: Vec<ShadowStackValue>
}

enum LookupError {
    ObjectNotFound,
}

impl ShadowStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_shadow_object(&mut self, base: Vaddr, size: usize) {
        // check if we are overwriting dead obj span
        let (idx, og_size) = match self.get_at(base) {
            Ok((og_sobj, i)) => (i, og_sobj.size()),
            Err(_) => {
                debug_assert!(false, "ShadowStack::add_shadow_object: untracked addr");
                return;
            }
        };

        self.data[idx] = ShadowStackValue::ShadowObject(ShadowObject {
            alloc_type: AllocType::Stack,
            base,
            limit: ShadowObject::limit(base, size),
            size,
        });

        // retain the remaining dead space
        // if the new object doesn't fill the full extent
        if og_size > size {
            self.data.insert(idx, ShadowStackValue::InvalidatedObject(base + size, og_size - size));
        }
        // If we didn't write through an invalidated object, we can drop subsequent frames
        else {
            self.data.truncate(idx + 1);
        }

    }

    fn get_at(&self, addr: Vaddr) -> Result<(&ShadowStackValue, usize), LookupError> {
        use LookupError::*;

        let n = self.data.len();
        if n == 0 { return Err(ObjectNotFound); }

        // fast path: the top frame (should be) the most common lookup target.
        let top_idx = n - 1;
        let top = &self.data[top_idx];
        if top.contains(addr) {
            return Ok((top, top_idx));
        }

        // easy out: below every tracked object
        if addr < top.base() {
            return Err(ObjectNotFound); // should we return a seperate ObjectOutOfBounds?
        }

        // binary search the shadow stack for value
        let idx = self.data.partition_point(|o| o.base() > addr);
        let obj = &self.data[idx];
        if obj.contains(addr) {
            Ok((obj, idx))
        } else {
            Err(ObjectNotFound)
        }
    }

    /*
        Invalidate a range of shadowstack.

        If that range spans to the end of the stack, we drop all the frames.
        Else, we are prepping to re-using a piece of stack
     */
    pub fn invalidate_at(&mut self, base: Vaddr, length: usize) {
        if length == 0 { return; }

        let Ok((_, start_idx)) = self.get_at(base) else {
            debug_assert!(false, "invalidate_at: untracked base");
            return;
        };
        let Ok((_, end_idx)) = self.get_at(base + length - 1) else {
            debug_assert!(false, "invalidate_at: untracked limit");
            return;
        };
        debug_assert!(end_idx <= start_idx);

        // pop all frames if range reaches the top of stack
        if start_idx == self.data.len() - 1 {
            self.data.truncate(end_idx);
            return;
        }

        // collapse the covered frames into one dead marker.
        self.data.drain(end_idx..start_idx);
        self.data[end_idx] = ShadowStackValue::InvalidatedObject(base, length);
    }

    // TODO: Does it make more sense to return something explicit
    //       when we search and get an invalidated stack object?
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {
        match self.get_at(addr) {
            Ok((ShadowStackValue::ShadowObject(sobj), _)) => Some(sobj),
            _ => None,
        }
    }
}

thread_local! {
    pub static SHADOW_STACK: RefCell<ShadowStack> = RefCell::new(ShadowStack::new());
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
    }
    #[test]
    fn bounds_testing() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x8000, 8);

        for x in 0x8000..0x8008 {
            assert!(table.search_intersection(x).is_some());
        }

        assert!(table.search_intersection(0x8009).is_none());
        assert!(table.search_intersection(0x7FFF).is_none());
    }

    #[test]
    #[should_panic]
    #[ignore = "not implemented"]
    fn test_bounds_invalid_address_panic() {
        // let table = ShadowObjectTable::new();
        //table.bounds(0xDEADBEEF).unwrap(); // should panic since there is no interesection
    }

    use super::{ShadowObject, ShadowStack, ShadowStackValue, Vaddr};

    fn stack_obj(base: Vaddr, size: usize) -> ShadowStackValue {
        ShadowStackValue::ShadowObject(ShadowObject {
            alloc_type: AllocType::Stack,
            base,
            limit: ShadowObject::limit(base, size),
            size,
        })
    }

    // NOTE: Generated by Opus 4.8
    //
    // Tests to ensure the stack grows descending and
    // properly resolves common lookups
    #[test]
    fn shadowstack_descending_lookup() {
        // Frames as the stack grows down: each new frame has a lower base, so
        // the vec is descending by base (top of stack = last element).
        let mut ss = ShadowStack::new();
        ss.data.push(stack_obj(0x3000, 0x100));
        ss.data.push(stack_obj(0x2000, 0x100));
        ss.data.push(stack_obj(0x1000, 0x100)); // top

        // Non-top frames must be found
        assert_eq!(ss.search_intersection(0x3050).map(|o| o.base), Some(0x3000));
        assert_eq!(ss.search_intersection(0x2050).map(|o| o.base), Some(0x2000));
        assert_eq!(ss.search_intersection(0x1050).map(|o| o.base), Some(0x1000));

        // Boundaries: base inclusive, base + size exclusive.
        assert_eq!(ss.search_intersection(0x3000).map(|o| o.base), Some(0x3000));
        assert!(ss.search_intersection(0x3100).is_none());

        // Below the top frame's base => below everything; gaps are misses.
        assert!(ss.search_intersection(0x0fff).is_none());
        assert!(ss.search_intersection(0x2500).is_none());
    }

    // NOTE: Generated by Opus 4.8
    //
    // Tests stack re-use where we tombstone invalidate a region
    // of shadow stack and then re-allocate a sobj inside of it
    // that may or may not fill that region entirely
    #[test]
    fn shadowstack_reuse() {
        // Exact reuse: a dead region reused by an equally
        // sized object leaves no dead space behind.
        let mut ss = ShadowStack::new();
        ss.data.push(ShadowStackValue::InvalidatedObject(0x1000, 0x100));
        assert!(ss.search_intersection(0x1050).is_none()); // dead before reuse

        ss.add_shadow_object(0x1000, 0x100);
        assert_eq!(ss.search_intersection(0x1050).map(|o| o.base), Some(0x1000)); // reused, live
        assert_eq!(ss.data.len(), 1); // no leftover dead space

        // Partial reuse: a smaller object reuses the base and leaves the
        // higher-base remainder dead.
        let mut ss = ShadowStack::new();
        ss.data.push(ShadowStackValue::InvalidatedObject(0x1000, 0x400));
        assert!(ss.search_intersection(0x1050).is_none()); // dead before reuse

        ss.add_shadow_object(0x1000, 0x100);
        assert_eq!(ss.search_intersection(0x1050).map(|o| o.base), Some(0x1000)); // reused, live
        assert!(ss.search_intersection(0x1200).is_none()); // remainder still dead

        // Descending invariant: dead remainder (higher base) precedes the live object.
        let bases: Vec<_> = ss.data.iter().map(|o| o.base()).collect();
        assert_eq!(bases, vec![0x1100, 0x1000]);
    }
}
