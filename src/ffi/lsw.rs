use libc::*;
use schemes::lsw::*;
use std::ffi::CStr;
use std::mem;
use std::mem::transmute;
use std::ops::Deref;
use std::string::String;
use std::{ptr, slice};

extern crate libc;


/// A BSW ABE Context
#[derive(PartialEq, Clone)]
pub struct KpAbeContext {
    pub _msk: KpAbeMasterKey,
    pub _pk: KpAbePublicKey,
}

#[no_mangle]
pub extern "C" fn kpabe_create() -> *mut KpAbeContext {
    let (_pk, _msk) = setup();
    let _ctx = unsafe {
        transmute(Box::new(KpAbeContext { _pk, _msk}))
    };
    _ctx
}

#[no_mangle]
pub extern "C" fn kpabe_destroy(ctx: *mut KpAbeContext) {
    let _ctx: Box<KpAbeContext> = unsafe { transmute(ctx) };
    let _context = _ctx.deref();
}

#[no_mangle]
pub extern "C" fn kpabe_encrypt(
    ctx: *mut KpAbeContext,
    attributes: *const c_char,
    pt: *mut u8,
    pt_len: u32,
    ct_buf: *mut *mut u8,
    ct_buf_len: *mut u32,
) -> i32 {
    let _cstr = unsafe { CStr::from_ptr(attributes).to_str().unwrap() };
    let mut _attrs = _cstr.split(",");
    let mut _attr_vec = Vec::new();
    for _a in _attrs {
        _attr_vec.push(String::from(_a));
    }
    let _ctx = unsafe { &*ctx };
    let _slice = unsafe { slice::from_raw_parts(pt, pt_len as usize) };
    let mut _data_vec = Vec::new();
    _data_vec.extend_from_slice(_slice);
    let _res = encrypt(&(_ctx._pk), &_attr_vec, &_data_vec);
    if let None = _res {
        return -1;
    }
    let _ct = _res.unwrap();
    let _bytes: &[u8] = unsafe { any_as_u8_slice(&_ct) };
    unsafe {
        let _size = (_bytes.len() + 1) as u32;
        *ct_buf = libc::malloc(_size as usize) as *mut u8;
        ptr::write_bytes(*ct_buf, 0, _size as usize);
        ptr::copy_nonoverlapping(_bytes.as_ptr(), *ct_buf, _bytes.len() as usize);

        ptr::copy_nonoverlapping(&_size, ct_buf_len, mem::size_of::<u32>());
    }
    0
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}
