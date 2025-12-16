// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::{LazyLock, nonpoison::Mutex};

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
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.limit - self.base + 1
    }

    /// Compute a limit from base and size
    pub fn limit(base: Vaddr, size: usize) -> Vaddr {
        base + size - 1
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
    pub fn new() -> ShadowObjectTable {
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
    pub fn invalidate_region(&mut self, base: Vaddr, limit: Vaddr) {
        self.table
            .extract_if(base..=limit, |_, _| true)
            .for_each(|_| {})
    }

    /// Finds a shadow object that contains `addr` in its bounds.
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {
        self.table.values().find(|sobj| sobj.contains(addr))
    }

    /// Finds a shadow object with a past_limit value matching the input
    pub fn search_invalid(&self, addr: Vaddr) -> Option<&ShadowObject> {
        self.table.values().find(|sobj| sobj.past_limit() == addr)
    }
}

/// Global list of active shadow objects
pub static ALIVE_OBJ_LIST: LazyLock<Mutex<ShadowObjectTable>> =
    LazyLock::new(|| Mutex::new(ShadowObjectTable::new()));
/// Global list of freed shadow objects
pub static FREED_OBJ_LIST: LazyLock<Mutex<ShadowObjectTable>> =
    LazyLock::new(|| Mutex::new(ShadowObjectTable::new()));
