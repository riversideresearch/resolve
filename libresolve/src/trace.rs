// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.
use libc::{c_char, c_float, c_void};
use std::{ffi::CStr, io::Write};
use std::fmt::Display;

use crate::buffer_writer::{BufferWriter};

pub fn libresolve_arg<T: Display>(arg: T, funct_name: *const u8) {
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);


    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[ARG] Function name: {}, value: {}", funct_str, arg);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

pub fn libresolve_ret<T: Display>(ret: T, funct_name: *const u8) {
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);


    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[RET] Function name: {}, value: {}", funct_str, ret);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_i8(arg: i8, funct_name: *const u8)
{
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
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[ARG] Function name: {}, value(pointer): {:?}", funct_str, arg);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_arg_opaque(funct_name: *const u8) {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

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
        &mut writer,
        "[ARG] Function {:?} has a runtime argument with opaque type, size: in progress",
        funct_str
    );

    let written = writer.as_bytes();
    unsafe {
        libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len());
    }
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i8(ret: i8, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i16(ret: i16, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i32(ret: i32, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_i64(ret: i64, funct_name: *const u8) 
{
   libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_float(ret: c_float, funct_name: *const u8) 
{
    libresolve_ret(ret, funct_name);
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_ptr(ret: *mut c_void, funct_name: *const u8) 
{
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };
    let _ = writeln!(&mut writer, "[RET] Function {} returned a pointer with address {:?}", funct_str, ret);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_void(funct_name: *const u8) 
{
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[RET] Function {} returned void", funct_str);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}

#[unsafe(no_mangle)]
pub extern "C" fn libresolve_bb(index: i64, funct_name: *const u8) 
{
    let mut buf =[0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);
    let funct_str = unsafe {
        if !funct_name.is_null() {
            CStr::from_ptr(funct_name as *const i8)
                .to_str()
                .unwrap_or("[invalid utf8]")
        } else {
            "[null]"
        }
    };

    let _ = writeln!(&mut writer, "[BB] Basic block index: {}, transition from {}", index, funct_str);
    let written = writer.as_bytes();
    unsafe { libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len())};
}


#[unsafe(no_mangle)]
pub extern "C" fn libresolve_ret_opaque(ptr: *mut c_void, funct_name: *const u8) {
    let mut buf = [0u8; 128];
    let mut writer = BufferWriter::new(&mut buf);

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
        &mut writer,
        "[RET] Function {:?} returned: {:?}",
        funct_str,
        ptr 
    );

    let written = writer.as_bytes();
    unsafe {
        libc::write(*RESOLVE_LOG_FD, written.as_ptr() as *const _, written.len());
    }
}
