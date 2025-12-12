// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::{LazyLock, nonpoison::Mutex};

//Declare alias for virtual address
pub type Vaddr = usize;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
// NOTE: Debug trait enables println!("{:?}")
pub enum AllocType {
    Unallocated,
    Unknown,
    Heap,
    Stack,
    #[allow(dead_code)] Global,
}

impl AllocType {
    pub fn is_allocation(&self) -> bool {
        match self {
            Self::Unallocated | Self::Unknown => false,
            _ => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowObject {
    pub alloc_type: AllocType, // Allocation type (Heap, Stack, Global, etc..)
    pub base: Vaddr,           // Base address of the allocated object mapped to u64
    pub limit: Vaddr,          // Last address of the allocated object
}

impl ShadowObject {
    /**
     * @brief - Returns the base / limit of this shadow object as RangeInclusive
     * @note - Useful for querying contains
     */
    pub fn bounds(&self) -> RangeInclusive<Vaddr> {
        self.base..=self.limit
    }

    pub fn contains(&self, addr: Vaddr) -> bool {
        self.bounds().contains(&addr)
    }

    #[allow(dead_code)]
    pub fn is_allocation(&self) -> bool {
        self.alloc_type.is_allocation()
    }

    /**
     * @brief - Computes size of shadow object from base and limit
     */
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.limit - self.base + 1
    }

    /// compute a limit from base + size
    pub fn limit(base: Vaddr, size: usize) -> Vaddr {
        base + size - 1
    }

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

    /**
     * @brief  - Adds a shadow object to the object list
     */
    pub fn add_shadow_object(&mut self, alloc_type: AllocType, base: Vaddr, size: usize) {
        let sobj = ShadowObject {
            alloc_type,
            base,
            limit: ShadowObject::limit(base, size),
        };
        self.table.insert(base, sobj);
    }

    /**
     * @brief - Looks through OBJLIST to find a shadow object that is within
     *          a given virtual address and limit
     * @input:  self, shadow object address  
     * @return: None if shadow object does not exist otherwise optional reference to shadow object  
     */
    pub fn search_intersection(&self, addr: Vaddr) -> Option<&ShadowObject> {
        self.table.values().find(|sobj| sobj.contains(addr))
    }
    
    /**
     * @brief - Looks through OBJLIST to find a shadow object with a past_limit value matching the input
     * @input:  self, shadow object address  
     * @return: None if shadow object does not exist otherwise optional reference to shadow object  
     */
    pub fn search_invalid(&self, addr: Vaddr) -> Option<&ShadowObject> {
        self.table.values().find(|sobj| sobj.past_limit() == addr)
    }
}

// static object lists to store all objects
pub static ALIVE_OBJ_LIST: LazyLock<Mutex<ShadowObjectTable>> =
    LazyLock::new(|| Mutex::new(ShadowObjectTable::new()));
pub static FREED_OBJ_LIST: LazyLock<Mutex<ShadowObjectTable>> =
    LazyLock::new(|| Mutex::new(ShadowObjectTable::new()));
