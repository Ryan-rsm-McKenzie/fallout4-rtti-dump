#![allow(non_snake_case)]

use crate::primitives::Rva;
use bytemuck::{
    AnyBitPattern,
    NoUninit,
};
use std::ffi::c_char;

#[derive(AnyBitPattern, Clone, Copy)]
#[repr(C)]
// TypeDescriptor/_TypeDescriptor
pub(crate) struct TypeDescriptor {
    pub(crate) pVFTable: usize,
    pub(crate) _UndecoratedName: usize,
    pub(crate) _DecoratedName: [c_char; 1], // null-terminated flex array
}

#[derive(AnyBitPattern, Clone, Copy, NoUninit)]
#[repr(C)]
// _s_RTTICompleteObjectLocator/_s__RTTICompleteObjectLocator/_s__RTTICompleteObjectLocator2/_RTTICompleteObjectLocator/__RTTICompleteObjectLocator
pub(crate) struct CompleteObjectLocator {
    pub(crate) signature: u32,
    pub(crate) offset: u32,
    pub(crate) cdOffset: u32,
    pub(crate) pTypeDescriptor: Rva,  // TypeDescriptor
    pub(crate) pClassDescriptor: Rva, // ClassHierarchyDescriptor
    pub(crate) pSelf: Rva,            // CompleteObjectLocator
}
