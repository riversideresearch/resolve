// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

#![feature(btree_cursors)]

mod remediate;
mod shadowobjs;
mod trace;
mod file;


use parking_lot::{Mutex, MutexGuard};

pub struct MutexWrap<T> {
    mutex: Mutex<T>,
}

impl<T> MutexWrap<T> {
    pub const fn new(x: T) -> Self {
        MutexWrap {
            mutex: Mutex::new(x),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.mutex.lock()
    }
}

