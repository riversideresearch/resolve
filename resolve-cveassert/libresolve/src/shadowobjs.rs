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
            self.data.insert(idx + 1, ShadowStackValue::InvalidatedObject(base + size, og_size - size));
        }
        // If we didn't write through an invalidated object, we can drop subsequent frames
        else {
            self.data.truncate(idx + 1);
        }

    }

    fn binary_search_window(&self, addr: Vaddr, mut lo: usize, mut hi: usize) -> Result<(&ShadowStackValue, usize), LookupError> {
        use LookupError::*;

        // Find the last object in [lo, hi) whose base <= addr.
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;

            if self.data[mid].base() <= addr {
                lo = mid;
            } else {
                hi = mid;
            }
        }

        let obj = &self.data[lo];

        if obj.contains(addr) {
            Ok((obj, lo))
        } else {
            Err(ObjectNotFound)
        }
    }

    fn get_at(&self, addr: Vaddr) -> Result<(&ShadowStackValue, usize), LookupError> {
        use LookupError::*;

        let n = self.data.len();
        if n == 0 { return Err(ObjectNotFound); }

        let last_idx = n - 1;
        let last = &self.data[last_idx];
        if last.contains(addr) {
            return Ok((last, last_idx));
        }

        // If addr is above the last object's base but not inside it,
        // then it cannot be in any earlier object, assuming sorted non-overlapping extents.
        if last.base() <= addr {
            return Err(ObjectNotFound);
        }

        // Gallop backwards until we find some object with base <= addr.
        let mut hi = last_idx; // upper bound
        let mut step = 1;

        loop {
            let lo = hi.saturating_sub(step);

            // We found a bucket that should contain the address:
            if self.data[lo].base() <= addr {
                // must be in [lo, hi).
                return self.binary_search_window(addr, lo, hi);
            }

            if lo == 0 {
                // Reached the end without finding the bucket
                return Err(ObjectNotFound);
            }

            // Giddyup
            hi = lo;
            step = step.saturating_mul(2);
        }
    }

    /*
        Invalidate a range of shadowstack.

        If that range spans to the end of the stack, we drop all the frames.
        Else, we are prepping to re-using a piece of stack
     */
    pub fn invalidate_at(&mut self, base: Vaddr, length: usize) {
        let Ok((_, start_idx )) = self.get_at(base) else {
            debug_assert!(false, "invalidate_at: untracked addr");
            return;
        };

        let Ok((_, end_idx )) = self.get_at(base + length) else {
            debug_assert!(false, "invalidate_at: untracked addr");
            return;
        };

        // Dropping >=1 entire frame(s)
        // TODO: does this need to be -1?
        if end_idx == self.data.len() {
            self.data.truncate(end_idx - start_idx);
        }

        // Invalidating objects within range
        // TODO: do we need to add comprehensive checks in places to make sure sobj lengths don't overlap,
        //       or is that a latent property of stack objects? What about in cases of re-use?
        self.data[start_idx] = ShadowStackValue::InvalidatedObject(base, length);
        
        if end_idx > start_idx {
            self.data.drain(start_idx+1..end_idx); // removes each affected obj at once (faster)
        }
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
        table.invalidate_at(0x1000);
        assert_eq!(table.table.len(), 1);
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
