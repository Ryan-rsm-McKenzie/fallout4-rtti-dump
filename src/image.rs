use crate::{
    abi::{
        CompleteObjectLocator,
        TypeDescriptor,
    },
    primitives::{
        Rva,
        Va,
    },
    rtti::TypeDescriptorInfo,
};
use anyhow::Context as _;
use bstr::{
    BStr,
    ByteSlice as _,
};
use bytemuck::AnyBitPattern;
use memchr::memmem;
use pelite::pe64::{
    Pe as _,
    PeFile,
};
use smallvec::SmallVec;
use std::mem;

pub(crate) struct ImageSection<'image> {
    pub(crate) virtual_address: Rva,
    pub(crate) bytes: &'image [u8],
}

impl<'image> ImageSection<'image> {
    fn try_locate(pe: &PeFile<'image>, section_name: &BStr) -> anyhow::Result<Self> {
        let section_header = pe
            .section_headers()
            .by_name(section_name)
            .with_context(|| {
                format!("failed to look up section: {}", section_name.to_str_lossy())
            })?;
        let bytes = pe.get_section_bytes(section_header).with_context(|| {
            format!(
                "failed to get bytes for section: {}",
                section_name.to_str_lossy()
            )
        })?;
        Ok(Self {
            virtual_address: section_header.VirtualAddress.into(),
            bytes,
        })
    }

    fn find<T>(&self, value: T) -> Option<usize>
    where
        T: AnyBitPattern + Eq,
    {
        self.find_iter(value).nth(0)
    }

    pub(crate) fn find_iter<T>(&self, value: T) -> impl Iterator<Item = usize> + 'image
    where
        T: AnyBitPattern + Eq,
    {
        let len = self.bytes.len() - self.bytes.len() % mem::size_of::<T>();
        let ints: &[T] = bytemuck::cast_slice(&self.bytes[..len]);
        ints.iter()
            .enumerate()
            .filter(move |(_, &x)| x == value)
            .map(|(i, _)| i * mem::size_of::<T>())
    }

    fn rva_to_offset(&self, rva: Rva) -> Option<usize> {
        let offset: usize = rva.checked_sub(self.virtual_address)?.try_into().ok()?;
        (offset < self.bytes.len()).then_some(offset)
    }
}

pub(crate) struct ImageSections<'image> {
    image_base: Va,
    pub(crate) data: ImageSection<'image>,
    rdata: ImageSection<'image>,
}

impl<'image> ImageSections<'image> {
    pub(crate) fn try_locate(pe: &PeFile<'image>) -> anyhow::Result<Self> {
        Ok(Self {
            image_base: pe.optional_header().ImageBase.into(),
            data: ImageSection::try_locate(pe, b".data".into())?,
            rdata: ImageSection::try_locate(pe, b".rdata".into())?,
        })
    }

    pub(crate) fn lookup_type_descriptor_vdtor(&self) -> anyhow::Result<Va> {
        let decorated_name = BStr::new(b".?AVtype_info@@");
        macro_rules! context {
            ($what:tt) => {
                || {
                    format!(
                        "failed to find `{}' for: {}",
                        $what,
                        decorated_name.to_str_lossy()
                    )
                }
            };
        }
        let type_descriptor_rva = memmem::find(self.data.bytes, decorated_name)
            .and_then(|offset| {
                let offset: Rva = offset
                    .checked_sub(mem::offset_of!(TypeDescriptor, _DecoratedName))?
                    .try_into()
                    .ok()?;
                offset.checked_add(self.data.virtual_address)
            })
            .with_context(context!("RTTI Type Descriptor"))?;
        let complete_object_locator_va = self
            .rdata
            .find(type_descriptor_rva)
            .and_then(|offset| {
                let offset: Va = offset
                    .checked_sub(mem::offset_of!(CompleteObjectLocator, pTypeDescriptor))?
                    .try_into()
                    .ok()?;
                offset
                    .checked_add(self.rdata.virtual_address.into())?
                    .checked_add(self.image_base)
            })
            .with_context(context!("RTTI Complete Object Locator"))?;
        self.rdata
            .find(complete_object_locator_va)
            .and_then(|offset| {
                let offset = offset.checked_add(mem::size_of::<u64>())?;
                if offset >= self.rdata.bytes.len() {
                    return None;
                }
                Va::try_from(offset)
                    .ok()?
                    .checked_add(self.rdata.virtual_address.into())?
                    .checked_add(self.image_base)
            })
            .with_context(context!("vftable"))
    }

    pub(crate) fn lookup_vftables(
        &self,
        type_descriptor_id: &TypeDescriptorInfo,
    ) -> anyhow::Result<SmallVec<[Rva; 1]>> {
        macro_rules! context {
            ($what:tt) => {
                || {
                    format!(
                        "failed to find `{}' for: {}",
                        $what,
                        type_descriptor_id.decorated_name.to_str_lossy()
                    )
                }
            };
        }
        let complete_object_locators = {
            let mut v = self
                .rdata
                .find_iter(type_descriptor_id.rva)
                .filter_map(|offset| {
                    let offset = offset
                        .checked_sub(mem::offset_of!(CompleteObjectLocator, pTypeDescriptor))?;
                    let va = Va::try_from(offset)
                        .ok()?
                        .checked_add(self.rdata.virtual_address.into())?
                        .checked_add(self.image_base)?;
                    let bytes = self
                        .rdata
                        .bytes
                        .get(offset..offset + mem::size_of::<CompleteObjectLocator>())?;
                    let complete_object_locator: &CompleteObjectLocator =
                        bytemuck::try_from_bytes(bytes).ok()?;
                    // BaseClassDescriptor and CompleteObjectLocator both point to TypeDescriptor,
                    // so we need to disambiguate them
                    self.rdata
                        .rva_to_offset(complete_object_locator.pClassDescriptor)
                        .map(|_| (complete_object_locator, va))
                })
                .collect::<Vec<_>>();
            v.sort_unstable_by_key(|x| x.0.offset);
            v
        };
        complete_object_locators
            .first()
            .and_then(|x| (x.0.offset == 0).then_some(()))
            .with_context(context!("RTTI Complete Object Locator"))?;
        complete_object_locators
            .iter()
            .map(|(_, complete_object_locator_va)| {
                self.rdata
                    .find(*complete_object_locator_va)
                    .and_then(|offset| {
                        let offset = offset.checked_add(mem::size_of::<u64>())?;
                        if offset >= self.rdata.bytes.len() {
                            return None;
                        }
                        Rva::try_from(offset)
                            .ok()?
                            .checked_add(self.rdata.virtual_address)
                    })
                    .with_context(context!("vftable"))
            })
            .collect()
    }
}
