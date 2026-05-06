// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use crate::MutexWrap;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
//use std::ops::Bound::Included;

pub type Vaddr = usize;

#[derive(Debug, Clone)]
pub struct Provenance {
    pub base: Vaddr,
    pub limit: Vaddr,
    // generation: Vaddr,
    // derived_from: Vaddr,
}

impl Provenance {
    
    pub fn bounds(&self) -> RangeInclusive<Vaddr> {
        self.base..=self.limit
    }

    pub fn contains(&self, addr: Vaddr) -> bool {
        self.bounds().contains(&addr)
    }
}

pub struct MetadataTable {
    table: BTreeMap<Vaddr, Provenance>,
}

impl MetadataTable {
    pub const fn new() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    pub fn add_ptr_metadata(&mut self, base: Vaddr, limit: Vaddr) {
        let prov = Provenance { 
            base, 
            limit: base + limit,
        };

        self.table.insert(base, prov);
    }

    pub fn invalidate_at(&mut self, base: Vaddr) {
        let _ = self.table.remove(&base);
    }

    pub fn search(&self, addr: Vaddr) -> Option<&Provenance> {
        todo!("Implement search fn ");
    }
}

pub static TRACKED_PTRS: MutexWrap<MetadataTable> = MutexWrap::new(MetadataTable::new());

//#[cfg(test)]

