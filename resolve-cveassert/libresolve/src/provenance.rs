// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use crate::MutexWrap;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::ops::Bound::Included;

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

    pub fn search_intersection(&self, addr: Vaddr) -> Option<&Provenance> {
        let cursor = self.table
            .upper_bound(Included(&addr));
        
        cursor.peek_prev()
            .filter(|(_, o)| o.contains(addr))
            .map(|(_, o)| o)
    }
}

pub static TRACKED_PTRS: MutexWrap<MetadataTable> = MutexWrap::new(MetadataTable::new());

#[cfg(test)]
mod tests {
    use crate::provenance::{MetadataTable};

    #[test]
    fn test_add_ptrs() {
        let mut table = MetadataTable::new();
        table.add_ptr_metadata(0x1000, 4);
        table.add_ptr_metadata(0x2000, 8);
    }

    #[test]
    fn test_remove_ptrs() {
        let mut table = MetadataTable::new();
        table.add_ptr_metadata(0x1000, 8);
        table.invalidate_at(0x1000);
        assert_eq!(table.table.len(), 0);
    }
}

