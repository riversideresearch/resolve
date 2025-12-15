// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{c_char, c_float, c_void};
use std::ffi::CStr;
use std::fmt::Display;

use log::info;

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

    info!("[ARG] Function name: {funct_str}, value: {arg}");
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

    info!("[RET] Function name: {funct_str}, value: {ret}");
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

    info!("[ARG] Function name: {funct_str}, value(pointer): {arg:?}");
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

    info!(
        "[ARG] Function {funct_str:?} has a runtime argument with opaque type, size: in progress"
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
    info!("[RET] Function {funct_str} returned a pointer with address {ret:?}");
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

    info!("[RET] Function {funct_str} returned void");
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

    info!("[BB] Basic block index: {index}, transition from {funct_str}");
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

    info!("[RET] Function {funct_str} returned: {ptr:?}");
}
