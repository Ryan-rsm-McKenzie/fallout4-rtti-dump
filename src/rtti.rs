use crate::{
    abi::TypeDescriptor,
    image::ImageSections,
    primitives::Rva,
};
use bstr::{
    BStr,
    BString,
    ByteVec as _,
};
use log::info;
use memchr::memmem::Finder;
use pelite::pe64::PeFile;
use smallvec::SmallVec;
use std::{
    collections::BTreeMap,
    ffi::CStr,
    mem,
};
use undname::Flags;

#[derive(Clone, Copy)]
pub(crate) struct StringHandle(usize);

impl StringHandle {
    pub(crate) fn resolve<'type_info>(
        self,
        type_info: &'type_info TypeInformation,
    ) -> &'type_info str {
        &type_info.undecorated_strings[self.0]
    }
}

impl From<usize> for StringHandle {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

pub(crate) struct TypeDescriptorInfo<'image> {
    pub(crate) rva: Rva,
    pub(crate) decorated_name: &'image BStr,
    pub(crate) undecorated_name: StringHandle,
}

pub(crate) struct ClassInfo<'image> {
    pub(crate) vftables: SmallVec<[Rva; 1]>,
    pub(crate) decorated_name: &'image BStr,
    pub(crate) undecorated_name: StringHandle,
}

pub(crate) struct TypeInformation<'image> {
    undecorated_strings: Vec<String>,
    pub(crate) type_descriptors: Vec<TypeDescriptorInfo<'image>>,
    pub(crate) classes: Vec<ClassInfo<'image>>,
}

impl<'image> TypeInformation<'image> {
    fn try_demangle(decorated_name: &BStr, buffer: &mut BString) -> Option<String> {
        const NEEDLE: &[u8] = b"`anonymous namespace'";
        undname::demangle_into(
            decorated_name,
            Flags::NO_MS_KEYWORDS
                | Flags::NO_FUNCTION_RETURNS
                | Flags::NO_ALLOCATION_LANGUAGE
                | Flags::NO_THISTYPE
                | Flags::NO_ACCESS_SPECIFIERS
                | Flags::NAME_ONLY,
            buffer,
        )
        .ok()?;
        if buffer == &b"float"[..] || buffer == &b"unsigned int"[..] {
            return None;
        }
        let finder = Finder::new(&NEEDLE);
        while let Some(pos) = finder.find(buffer) {
            buffer.drain(pos..pos + NEEDLE.len());
        }
        let result = buffer
            .iter()
            .filter_map(|&x| match x {
                b' ' | b'&' | b'*' | b'`' | b'\'' | b'\\' | b'-' => None,
                b'(' | b')' | b'<' | b'>' | b',' | b':' => Some(b'_'),
                _ => Some(x),
            })
            .collect::<Vec<_>>()
            .into_string_lossy();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub(crate) fn try_scrape(pe: &PeFile<'image>) -> anyhow::Result<Self> {
        info!("scraping type information...");
        let sections = ImageSections::try_locate(pe)?;
        let mut undecorated_strings = Vec::new();
        let type_descriptors: Vec<_> = {
            let vdtor = sections.lookup_type_descriptor_vdtor()?;
            let mut buffer = BString::default();
            sections
                .data
                .find_iter(vdtor)
                .filter_map(|type_descriptor_offset| {
                    let rva = Rva::try_from(type_descriptor_offset)
                        .ok()?
                        .checked_add(sections.data.virtual_address)?;
                    let offset = type_descriptor_offset
                        .checked_add(mem::offset_of!(TypeDescriptor, _DecoratedName))?;
                    let bytes = sections.data.bytes.get(offset..)?;
                    let decorated_name: &BStr =
                        CStr::from_bytes_until_nul(bytes).ok()?.to_bytes().into();
                    let undecorated_name = Self::try_demangle(decorated_name, &mut buffer)?;
                    undecorated_strings.push(undecorated_name.clone());
                    Some((
                        undecorated_name,
                        TypeDescriptorInfo {
                            rva,
                            decorated_name,
                            undecorated_name: (undecorated_strings.len() - 1).into(),
                        },
                    ))
                })
                .collect::<BTreeMap<_, _>>()
                .into_values()
                .collect()
        };
        let classes = type_descriptors
            .iter()
            .filter_map(|type_descriptor| {
                sections
                    .lookup_vftables(type_descriptor)
                    .map(|vftables| ClassInfo {
                        vftables,
                        decorated_name: type_descriptor.decorated_name,
                        undecorated_name: type_descriptor.undecorated_name,
                    })
                    .ok()
            })
            .collect();
        Ok(Self {
            undecorated_strings,
            type_descriptors,
            classes,
        })
    }
}
