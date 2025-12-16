// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{c_char, c_float, c_void};
use std::fmt::Display;
use std::{ffi::CStr, io::Write};

use crate::RESOLVE_LOG_FILE;

pub fn libresolve_arg(arg: impl Display, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[ARG] Function name: {}, value: {}",
        funct_str,
        arg
    );
}

pub fn libresolve_ret(ret: impl Display, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[RET] Function name: {}, value: {}",
        funct_str,
        ret
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i8(arg: i8, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i16(arg: i16, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i32(arg: i32, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i64(arg: i64, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_float(arg: c_float, funct_name: *const u8) {
    libresolve_arg(arg, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_ptr(arg: *mut c_void, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[ARG] Function name: {}, value(pointer): {:?}",
        funct_str,
        arg
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_opaque(funct_name: *const u8) {
    let funct_str = unsafe {
        if funct_name.is_null() {
            "[invalid pointer]"
        } else {
            CStr::from_ptr(funct_name as *const c_char)
                .to_str()
                .unwrap_or("[invalid utf8]")
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[ARG] Function {:?} has a runtime argument with opaque type, size: in progress",
        funct_str
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i8(ret: i8, funct_name: *const u8) {
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i16(ret: i16, funct_name: *const u8) {
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i32(ret: i32, funct_name: *const u8) {
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i64(ret: i64, funct_name: *const u8) {
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_float(ret: c_float, funct_name: *const u8) {
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_ptr(ret: *mut c_void, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };
    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[RET] Function {} returned a pointer with address {:?}",
        funct_str,
        ret
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_void(funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[RET] Function {} returned void",
        funct_str
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_bb(index: i64, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[BB] Basic block index: {}, transition from {}",
        index,
        funct_str
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_opaque(ptr: *mut c_void, funct_name: *const u8) {
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const c_char)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(
        &mut RESOLVE_LOG_FILE.lock(),
        "[RET] Function {:?} returned: {:?}",
        funct_str,
        ptr
    );
}
