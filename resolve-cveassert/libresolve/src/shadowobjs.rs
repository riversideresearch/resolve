// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use crate::MutexWrap;
use crate::shadowobjs::LookupError::{AddrOOB, ObjectNotFound};
use crate::shadowobjs::ShadowStackObject::FrameFrontPtr;
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

/*
    Stack shadow object shape:
    [frame 0]   [  frame 1  ]
    [ | | | ][*][ | | | | | ][*] -> (growth direction)
    <---------| <-------------|  

    We grow by appending ShadowObjects to the end of the Vector,
    and inserting new FrameFrontPtrs when we push new frames.
    These FrameFrontPtrs reference the beginning of the pervious
    frame, letting us backwards traverse in order to search
*/
enum ShadowStackObject {
    ShadowObject(ShadowObject),
    FrameFrontPtr(usize)
}

pub struct ShadowStack {
    data: Vec<ShadowStackObject>,
    tip: usize
}

enum LookupError {
    AddrOOB,
    ObjectNotFound,
}

impl ShadowStack {
    pub fn new() -> Self {
        Self {
            data: vec![ShadowStackObject::FrameFrontPtr(0)],
            tip: 1,
        }
    }

    pub fn add_shadow_object(&mut self, base: Vaddr, size: usize) {
        let sobj = ShadowObject {
            alloc_type: AllocType::Stack,
            base,
            limit: ShadowObject::limit(base, size),
            size,
        };
        let ffp = self.data.pop().expect("Missing frame front pointer");
        self.data.push(ShadowStackObject::ShadowObject(sobj));
        self.data.push(ffp);

        self.tip += 1;
    }

    /*
        Walk the stack and return an index
        and object reference if found
     */
    fn locate(&self, addr: Vaddr) -> Result<(&ShadowObject, usize), LookupError> {
        use LookupError::*;

        if self.data.len() <= 1 {
            return Err(ObjectNotFound); // only sentinel ffp; empty
        }

        // current frame's trailing ffp
        let mut ffp_idx = self.tip - 1;

        loop {
            // grab the frame start idx value in trailing ffp
            let ShadowStackObject::FrameFrontPtr(frame_start_idx) =
                self.data.get(ffp_idx).expect("Malformed shadow stack head!")
            else {
                panic!("Malformed shadow stack head!")
            };
            let frame_start_idx = *frame_start_idx;

            // grab the first sobj in frame
            let first = match self.data.get(frame_start_idx).expect("Malformed shadow stack") {
                ShadowStackObject::ShadowObject(obj) => obj,
                ShadowStackObject::FrameFrontPtr(_) => {
                    // edge case: empty frame should skip to older frame
                    if frame_start_idx == 0 {
                        return Err(LookupError::ObjectNotFound);
                    }
                    ffp_idx = frame_start_idx - 1;
                    continue;
                }
            };

            // keep jumping frames until
            // first sobj addr < desired addr
            if first.base > addr {
                if frame_start_idx == 0 {
                    return Err(ObjectNotFound); // checked everything
                }
                // previous frames trailing FFP
                ffp_idx = frame_start_idx - 1;
                continue;
            }

            // addr is in (or above) this frame: scan [frame_start_idx, ffp_idx)
            let mut scan = frame_start_idx;
            while scan < ffp_idx {
                let ShadowStackObject::ShadowObject(sobj) =
                    self.data.get(scan).expect("Malformed shadow stack!")
                else {
                    panic!("Malformed shadow stack ordering!")
                };
                if sobj.contains(addr) {
                    return Ok((sobj, scan));
                }
                scan += 1;
            }
            return Err(ObjectNotFound);
        }
    }

    pub fn invalidate_at(&self, base: Vaddr) {
        // TODO
    }

    /*
        Perform a backwards search from tip by jumping
        to current frame start and comparing Vaddr. If 
        Vaddr < FrameVaddr we jump back until the condition
        is met, then incrementally search the found frame to
        resolve the shadowobject.
     */
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {

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
