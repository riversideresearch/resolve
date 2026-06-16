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
    pub fn new(ty: AllocType, base: Vaddr, size: usize) -> Self {
        Self {
            alloc_type: ty,
            base,
            limit: ShadowObject::limit(base, size),
            size
        }
    }
    
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

    /// Computes the size of the shadow object from its base and limit
    pub fn size(&self) -> usize {
        self.size
    }

    /// Compute a limit from base and size
    pub fn limit(base: Vaddr, size: usize) -> Vaddr {
        if size == 0 { base } else { base.saturating_add(size - 1) }
    }

    /// Compute the sentinel pointer value for this object, 1 past its limit
    pub fn past_limit(&self) -> Vaddr {
        self.limit.saturating_add(1)
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
        self.table.insert(base, ShadowObject::new(alloc_type, base, size));
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

// data must be ordered descending (downward growing stack on x86)
// so push/pop are O(1) at the end.
#[derive(Default)]
pub struct ShadowStack {
    data: Vec<ShadowObject>
}

enum LookupError {
    ObjectNotFound,
}

impl ShadowStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_shadow_object(&mut self, base: Vaddr, size: usize) {
        let new_end = base.checked_add(size)
            .expect("add_shadow_object: object overflows the address space"); // exclusive

        let Ok((reused, idx)) = self.get_at(base) else {
            // most common: pushing a new obj onto the end of the stack
            assert!(self.data.last().map_or(true, |top| new_end <= top.base),
                "ShadowStack::add_shadow_object: new object overlaps the stack top");
            self.data.push(ShadowObject::new(AllocType::Stack, base, size));
            return;
        };

        let slot_base = reused.base;
        let slot_end = slot_base + reused.size();
        let reused_live = reused.alloc_type != AllocType::Unallocated;

        // also common: new object is being pushed after program has fallen
        //              back a few stack frames. Overwrite and truncate.
        if reused_live {
            assert!(slot_base == base,
                "ShadowStack::add_shadow_object: re-push lands inside a live object");
            assert!(idx == 0 || new_end <= self.data[idx - 1].base,
                "ShadowStack::add_shadow_object: object overlaps the frame above");
            self.data[idx] = ShadowObject::new(AllocType::Stack, base, size);
            self.data.truncate(idx + 1); // drop everything more recent
        }
        else {
            // least common: stack re-use (new alloca inside previously invalidated region)
            assert!(new_end <= slot_end,
                "ShadowStack::add_shadow_object: object overflows its slot");
            self.data[idx] = ShadowObject::new(AllocType::Stack, base, size);

            // retain invalidated padding around object
            if slot_base < base {
                self.data.insert(idx + 1, ShadowObject::new(AllocType::Unallocated, slot_base, base - slot_base));
            }
            if new_end < slot_end {
                self.data.insert(idx, ShadowObject::new(AllocType::Unallocated, new_end, slot_end - new_end));
            }
        }
    }

    fn get_at(&self, addr: Vaddr) -> Result<(&ShadowObject, usize), LookupError> {
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
        if addr < top.base {
            return Err(ObjectNotFound); // should we return a seperate ObjectOutOfBounds?
        }

        // binary search the shadow stack for value
        let idx = self.data.partition_point(|o| o.base > addr);
        let obj = &self.data[idx];
        if obj.contains(addr) {
            Ok((obj, idx))
        } else {
            Err(ObjectNotFound)
        }
    }

    /*
        Invalidate the address range [base, base + length).

        `base` and `base + length` must each land exactly on a tracked object
        boundary. The range may span several whole objects (live or dead), but
        it may not bisect one. The spanned entries are dropped and replaced by
        a single dead marker.
     */
    pub fn invalidate_at(&mut self, base: Vaddr, length: usize) {
        if length == 0 { return; }
        let end = base.checked_add(length)
            .expect("invalidate_at: range overflows the address space"); // exclusive

        // entry holding `base` (lowest address in the range)
        let (start_idx, lo_base) = match self.get_at(base) {
            Ok((v, idx)) => (idx, v.base),
            Err(_) => { debug_assert!(false, "invalidate_at: untracked base"); return; }
        };
        assert!(lo_base == base,
            "invalidate_at: range start 0x{base:x} is not an object boundary");

        // entry holding `end - 1` (highest address in the range)
        let (end_idx, hi_end) = match self.get_at(end - 1) {
            Ok((v, idx)) => (idx, v.base + v.size()),
            Err(_) => { debug_assert!(false, "invalidate_at: untracked limit"); return; }
        };
        assert!(hi_end == end,
            "invalidate_at: range end 0x{end:x} is not an object boundary");

        debug_assert!(end_idx <= start_idx);

        let was_top = start_idx == self.data.len() - 1;
        self.data.drain(end_idx..=start_idx);

        // if we didn't reach the top, leave a dead marker for the invalidated range
        if !was_top {
            self.data.insert(end_idx, ShadowObject::new(AllocType::Unallocated, base, length));
        }
    }

    // TODO: Does it make more sense to return something explicit
    //       when we search and get an invalidated stack object?
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {
        // exact containment in a live object
        if let Ok((sobj, _)) = self.get_at(addr)
        && sobj.alloc_type != AllocType::Unallocated
        {
            return Some(sobj);
        }

        // edge case: GEP remediation one-past
        if let Some(prev) = addr.checked_sub(1)
        && let Ok((sobj, _)) = self.get_at(prev)
        && sobj.alloc_type != AllocType::Unallocated
        && sobj.past_limit() == addr
        {
            return Some(sobj);
        }

        None
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
}