// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use crate::MutexWrap;
use log::warn;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::Bound::Included;
use std::ops::RangeInclusive;

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
    pub alloc_type: AllocType,
    pub base: Vaddr,
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
        if size == 0 { base } else { base + (size - 1) }
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
        let cursor = self.table.upper_bound(Included(&addr));

        cursor
            .peek_prev()
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

        // A zero-byte alloca tracks nothing and would create a degenerate entry
        if size == 0 { return; }

        let Ok((reused, idx)) = self.get_at(base) else {
            // `base` is not inside any tracked entry
            if self.data.last().map_or(true, |top| new_end <= top.base) {
                // overwhelmingly common: clean append below the current top. O(1)
                self.data.push(ShadowObject::new(AllocType::Stack, base, size));
            } else {
                // out-of-order sibling or a stale frame above us:
                // place at the sorted position, reconciling any
                // overlap with higher (necessarily stale) entries. newest-wins.
                self.insert_reconcile(base, size, new_end);
            }
            self.assert_descending();
            return;
        };

        let slot_base = reused.base;
        let slot_end = slot_base + reused.size();
        let reused_live = reused.alloc_type != AllocType::Unallocated;

        // also common: new object is being pushed after program has fallen
        //              back a few stack frames. Overwrite and truncate.
        if reused_live {
            if slot_base < base || (idx > 0 && new_end > self.data[idx - 1].base) {
                // `base` lands strictly inside a live entry, or a re-push at the
                // exact base grew up into the frame above. Either way the entry we
                // land in (and everything deeper) is a stale frame we're reusing:
                // drop it, then reconcile against any overlap above. newest-wins.
                self.data.truncate(idx);
                self.insert_reconcile(base, size, new_end);
            } else {
                self.data[idx] = ShadowObject::new(AllocType::Stack, base, size);
                self.data.truncate(idx + 1); // drop everything more recent
            }
        }
        else {
            // least common: invalidated stack re-use (new alloca inside previously invalidated region)
            if new_end > slot_end {
                // object overflows its dead slot into the entry above; reconcile.
                self.insert_reconcile(base, size, new_end);
            } else {
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
        self.assert_descending();
    }

    /// Remove every entry overlapping [lo, hi) from the descending Vec, trimming
    /// straddlers so the region becomes a clean hole and preserving each survivors
    /// alloc_type. Returns (hole_idx, reached_top, removed): hole_idx is the
    /// sorted index the now-empty [lo, hi) region occupies; reached_top is true
    /// if the removed run reached the stack top (lowest entry) with nothing
    /// surviving below it; removed is false if the range overlapped nothing.
    fn clear_interval(&mut self, lo: Vaddr, hi: Vaddr) -> (usize, bool, bool) {
        let len = self.data.len();

        // first index with base < hi, then extend over the contiguous run that also
        // reaches above `lo` (an entry overlaps [lo, hi) iff base < hi && end > lo).
        let start = self.data.partition_point(|o| o.base >= hi);
        let mut k = start;
        while k < len && self.data[k].base + self.data[k].size() > lo {
            k += 1;
        }
        if start == k {
            return (start, false, false); // nothing overlaps; hole belongs at `start`
        }

        // capture straddler info by value before draining
        let upper_base  = self.data[start].base;
        let upper_end = upper_base + self.data[start].size(); // exclusive
        let upper_ty = self.data[start].alloc_type;
        let lower_base = self.data[k - 1].base;
        let lower_ty = self.data[k - 1].alloc_type;

        let upper_straddles = upper_end > hi;
        let lower_straddles = lower_base < lo;
        let reached_top = k == len && !lower_straddles;

        if self.data[start..k].iter().any(|o| o.alloc_type != AllocType::Unallocated) {
            warn!("ShadowStack: reconciled a live entry while resolving [0x{lo:x}, 0x{hi:x}) \
                   (stale frame or out-of-order alloca)");
        }

        self.data.drain(start..k);

        let mut ins = start;
        if upper_straddles {
            self.data.insert(ins, ShadowObject::new(upper_ty, hi, upper_end - hi));
            ins += 1;
        }
        if lower_straddles {
            self.data.insert(ins, ShadowObject::new(lower_ty, lower_base, lo - lower_base));
        }

        (start + upper_straddles as usize, reached_top, true)
    }

    /// Insert a live sobj spanning [base, new_end) at its sorted
    /// position, clearing anything it overlaps.
    fn insert_reconcile(&mut self, base: Vaddr, size: usize, new_end: Vaddr) {
        let (hole, _, _) = self.clear_interval(base, new_end);
        self.data.insert(hole, ShadowObject::new(AllocType::Stack, base, size));
    }

    #[cfg(debug_assertions)]
    fn assert_descending(&self) {
        for w in self.data.windows(2) {
            assert!(w[0].base > w[1].limit,
                "ShadowStack invariant violated: 0x{:x}..=0x{:x} not strictly above 0x{:x}..=0x{:x}",
                w[1].base, w[1].limit, w[0].base, w[0].limit);
        }
    }
    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn assert_descending(&self) {}

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

        Clears the range, trimming any entry that straddles a boundary.
        If the range did not reach the stack top, a single dead marker
        is left in its place.
     */
    pub fn invalidate_at(&mut self, base: Vaddr, length: usize) {
        if length == 0 { return; }
        let end = base.checked_add(length)
            .expect("invalidate_at: range overflows the address space"); // exclusive

        let (hole, reached_top, removed) = self.clear_interval(base, end);

        // leave a dead marker only if we cleared real entries below the top;
        // an already-evicted/untracked range is a silent no-op (stale frame,
        // double lifetime.end, etc.)
        if removed && !reached_top {
            self.data.insert(hole, ShadowObject::new(AllocType::Unallocated, base, length));
        }
        self.assert_descending();
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

//         //table.print_shadow_obj();
//     }

<<<<<<< HEAD
    #[test]
    fn test_remove_shadow_objects() {
        let mut table = ShadowObjectTable::new();
        table.add_shadow_object(AllocType::Heap, 0x1000, 8);
        table.add_shadow_object(AllocType::Stack, 0x2000, 16);
        table.invalidate_at(0x1000);
        assert_eq!(table.table.len(), 1);
    }
=======
//     #[test]
//     fn test_remove_shadow_objects() {
//         let mut table = ShadowObjectTable::new();
//         table.add_shadow_object(AllocType::Heap, 0x1000, 8);
//         table.add_shadow_object(AllocType::Stack, 0x2000, 16);
//     }
>>>>>>> ec6b0f1 (remediate.rs: Make sure all logging is commented out for poller testing.)

//     #[test]
//     fn test_search_intersection_found() {
//         let mut table = ShadowObjectTable::new();
//         table.add_shadow_object(AllocType::Global, 0x3000, 4);

//         let result = table.search_intersection(0x3002);
//         assert!(result.is_some());
//         assert_eq!(result.unwrap().alloc_type, AllocType::Global);
//     }

//     #[test]
//     fn test_search_intersection_not_found() {
//         let mut table = ShadowObjectTable::new();
//         table.add_shadow_object(AllocType::Heap, 0x4000, 4);

//         let result = table.search_intersection(0x5000);
//         assert!(result.is_none());
//     }

//     #[test]
//     fn test_is_allocation() {
//         let mut table = ShadowObjectTable::new();
//         table.add_shadow_object(AllocType::Stack, 0x6000, 8);

//         let typ = table.search_intersection(0x6004).unwrap().alloc_type;
//         assert_eq!(typ, AllocType::Stack);
//     }
//     #[test]
//     fn bounds_testing() {
//         let mut table = ShadowObjectTable::new();
//         table.add_shadow_object(AllocType::Heap, 0x8000, 8);

//         for x in 0x8000..0x8008 {
//             assert!(table.search_intersection(x).is_some());
//         }

        assert!(table.search_intersection(0x8009).is_none());
        assert!(table.search_intersection(0x7FFF).is_none());
    }

    use super::ShadowStack;

    /// (alloc_type, base, size) of each entry, top-of-Vec (highest addr) first.
    fn layout(s: &ShadowStack) -> Vec<(AllocType, usize, usize)> {
        s.data.iter().map(|o| (o.alloc_type, o.base, o.size())).collect()
    }

    #[test]
    fn stack_invalidate_top_pops_clean() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A (outer)
        s.add_shadow_object(0x0F00, 0x100); // B (inner / top)

        // B's one-past sentinel resolves to B (GEP one-past remediation).
        assert!(s.search_intersection(0x0F00 + 0x100).is_some());

        s.invalidate_at(0x0F00, 0x100); // top -> drained, no marker

        assert!(s.search_intersection(0x0F00).is_none());
        let a = s.search_intersection(0x1000).expect("A still live");
        assert_eq!(a.base, 0x1000);
        assert_eq!(a.alloc_type, AllocType::Stack);
    }

    #[test]
    fn stack_implicit_multiframe_drop() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A
        s.add_shadow_object(0x0F00, 0x100); // B
        s.add_shadow_object(0x0E00, 0x100); // D (top)

        // smaller frame F reuses B's slot.
        s.add_shadow_object(0x0F00, 0x80); // F

        // D's region was implicitly dropped.
        assert!(s.search_intersection(0x0E00).is_none());
        assert!(s.search_intersection(0x0E80).is_none());

        // F is live at B's base.
        let f = s.search_intersection(0x0F00).expect("F live");
        assert_eq!(f.base, 0x0F00);
        assert_eq!(f.size(), 0x80);
        assert_eq!(f.alloc_type, AllocType::Stack);

        // A untouched.
        assert!(s.search_intersection(0x1000).is_some());
    }

    /// Stack reuse into a previously-invalidated (dead) region
    #[test]
    fn stack_reuse_into_invalidated_region() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A
        s.add_shadow_object(0x0F00, 0x100); // B
        s.add_shadow_object(0x0E00, 0x100); // C (top)

        s.invalidate_at(0x0F00, 0x100);
        assert!(s.search_intersection(0x0F80).is_none()); // interior of dead B, not live

        // smaller alloca reuses the middle of B's dead slot.
        s.add_shadow_object(0x0F40, 0x40); // 0xF40..0xF7F

        let n = s.search_intersection(0x0F40).expect("reused obj live");
        assert_eq!(n.base, 0x0F40);
        assert_eq!(n.size(), 0x40);

        // Padding on both sides of the reused object stays dead
        assert!(s.search_intersection(0x0F20).is_none()); // low padding interior
        assert!(s.search_intersection(0x0FC0).is_none()); // high padding interior

        // Neighbors still live
        assert!(s.search_intersection(0x1000).is_some()); // A
        assert!(s.search_intersection(0x0E00).is_some()); // C
    }

    /// Out-of-order siblings in one frame
    #[test]
    fn stack_ascending_siblings_reconcile() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x10); // a
        s.add_shadow_object(0x1020, 0x10); // b, above a
        s.add_shadow_object(0x1010, 0x10); // c, between a and b

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x1020, 0x10),
            (AllocType::Stack, 0x1010, 0x10),
            (AllocType::Stack, 0x1000, 0x10),
        ]);

        assert_eq!(s.search_intersection(0x1000).unwrap().base, 0x1000);
        assert_eq!(s.search_intersection(0x1010).unwrap().base, 0x1010);
        assert_eq!(s.search_intersection(0x1020).unwrap().base, 0x1020);
        // one-past `b` resolves to `b` (GEP one-past remediation)
        assert!(s.search_intersection(0x1030).is_some());
    }

    /// Registration order must not affect the resulting layout: the reconcile
    /// path produces the same structure as the in-order fast path.
    #[test]
    fn stack_order_independent_layout() {
        let mut asc = ShadowStack::new();
        asc.add_shadow_object(0x1000, 0x10);
        asc.add_shadow_object(0x1020, 0x10);
        asc.add_shadow_object(0x1010, 0x10);

        let mut desc = ShadowStack::new();
        desc.add_shadow_object(0x1020, 0x10);
        desc.add_shadow_object(0x1010, 0x10);
        desc.add_shadow_object(0x1000, 0x10);

        assert_eq!(layout(&asc), layout(&desc));
    }

    /// A sibling landing in a gap left by a clean append
    #[test]
    fn stack_siblings_across_gap() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1FE0, 0x10); // B
        s.add_shadow_object(0x2000, 0x10); // A, above B (push-above)
        s.add_shadow_object(0x1FC0, 0x10); // D, below B via clean append -> B..D gap
        s.add_shadow_object(0x1FD0, 0x10); // C, lands in the B..D gap

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x2000, 0x10),
            (AllocType::Stack, 0x1FE0, 0x10),
            (AllocType::Stack, 0x1FD0, 0x10),
            (AllocType::Stack, 0x1FC0, 0x10),
        ]);
    }

    /// A new frame whose alloca spans several stale (un-torn-down) frames: the
    /// stale entries should be evicted (newest-wins), the outer frame untouched.
    #[test]
    fn stack_evict_stale_frames() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x2000, 0x100); // X, outer (stays live)
        s.add_shadow_object(0x1100, 0x80);  // S1, stale
        s.add_shadow_object(0x1080, 0x80);  // S2, stale
        s.add_shadow_object(0x1000, 0x180); // N spans S1+S2 exactly

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x2000, 0x100),
            (AllocType::Stack, 0x1000, 0x180), // 0x1000..=0x117F
        ]);
        assert_eq!(s.search_intersection(0x1080).unwrap().base, 0x1000);
        assert_eq!(s.search_intersection(0x1100).unwrap().base, 0x1000);
        assert!(s.search_intersection(0x2000).is_some()); // X intact
    }

    /// New object partially overlaps a stale entry above: that entry's low end is
    /// trimmed (base moves up), keeping its surviving high portion.
    #[test]
    fn stack_trim_straddler() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x2000, 0x100); // X
        s.add_shadow_object(0x1100, 0x100); // S1 0x1100..=0x11FF
        s.add_shadow_object(0x1080, 0x80);  // S2 0x1080..=0x10FF
        s.add_shadow_object(0x1000, 0x150); // N 0x1000..=0x114F, trims S1's low end

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x2000, 0x100),
            (AllocType::Stack, 0x1150, 0xB0),  // S1' 0x1150..=0x11FF
            (AllocType::Stack, 0x1000, 0x150), // N
        ]);
        assert_eq!(s.search_intersection(0x1140).unwrap().base, 0x1000); // N owns it now
        assert_eq!(s.search_intersection(0x1150).unwrap().base, 0x1150); // trimmed S1'
    }

    /// Insert far above everything tracked (guards the `start == 0` underflow path).
    #[test]
    fn stack_insert_above_all() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A
        s.add_shadow_object(0x3000, 0x10);  // N far above

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x3000, 0x10),
            (AllocType::Stack, 0x1000, 0x100),
        ]);
    }

    /// New object grows up into the current top, trimming its low end (the upper
    /// straddler reaches the stack top).
    #[test]
    fn stack_trim_top() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A 0x1000..=0x10FF
        s.add_shadow_object(0x0F00, 0x180); // N 0x0F00..=0x107F grows up into A

        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x1080, 0x80),  // A' 0x1080..=0x10FF
            (AllocType::Stack, 0x0F00, 0x180), // N
        ]);
        assert_eq!(s.search_intersection(0x1000).unwrap().base, 0x0F00); // A's low half is N
        assert_eq!(s.search_intersection(0x1080).unwrap().base, 0x1080); // A' survives
    }

    /// A lifetime.start re-firing in a loop re-registers the same base/size;
    /// the layout must stay stable.
    #[test]
    fn stack_repeated_lifetime_start_stable() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x1000, 0x100); // A
        s.add_shadow_object(0x0F00, 0x80);  // B
        for _ in 0..3 {
            s.add_shadow_object(0x0F00, 0x80); // re-register B
        }
        assert_eq!(layout(&s), vec![
            (AllocType::Stack, 0x1000, 0x100),
            (AllocType::Stack, 0x0F00, 0x80),
        ]);
    }

    /// After a reconcile trims a neighbor, a later `invalidate_at` called with the
    /// *original* (now non-boundary-aligned) bounds must not panic.
    #[test]
    fn stack_invalidate_after_trim() {
        let mut s = ShadowStack::new();
        s.add_shadow_object(0x2000, 0x100); // X
        s.add_shadow_object(0x1100, 0x100); // S1
        s.add_shadow_object(0x1080, 0x80);  // S2
        s.add_shadow_object(0x1000, 0x150); // N trims S1 -> S1'@0x1150/0xB0

        // S1's original bounds no longer land on a tracked boundary.
        s.invalidate_at(0x1100, 0x100); // must not panic (boundary-tolerant)

        assert!(s.search_intersection(0x2000).is_some()); // X still live
    }

    #[test]
    #[should_panic]
    #[ignore = "not implemented"]
    fn test_bounds_invalid_address_panic() {
        // let table = ShadowObjectTable::new();
        //table.bounds(0xDEADBEEF).unwrap(); // should panic since there is no interesection
    }
}