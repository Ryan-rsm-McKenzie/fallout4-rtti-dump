#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Context as _;
use bstr::{
    BStr,
    BString,
    ByteSlice as _,
    ByteVec as _,
};
use bytemuck::{
    AnyBitPattern,
    NoUninit,
};
use byteorder::{
    LittleEndian,
    ReadBytesExt as _,
};
use log::{
    info,
    warn,
};
use memchr::memmem::{
    self,
    Finder,
};
use pelite::pe64::{
    Pe as _,
    PeFile,
};
use smallvec::SmallVec;
use std::{
    collections::BTreeMap,
    ffi::CStr,
    fmt::{
        self,
        Display,
        Formatter,
        Write as _,
    },
    fs::{
        self,
        File,
    },
    io::Write as _,
    mem,
    num::TryFromIntError,
    path::Path,
};
use undname::Flags;

#[repr(transparent)]
#[derive(AnyBitPattern, Clone, Copy, Eq, NoUninit, Ord, PartialEq, PartialOrd)]
struct Va(u64);

impl Va {
    fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self::from)
    }
}

impl From<Rva> for Va {
    fn from(value: Rva) -> Self {
        Self(value.0.into())
    }
}

impl From<u64> for Va {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<usize> for Va {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

#[repr(transparent)]
#[derive(AnyBitPattern, Clone, Copy, Eq, NoUninit, Ord, PartialEq, PartialOrd)]
struct Rva(u32);

impl Rva {
    fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self::from)
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self::from)
    }
}

impl Display for Rva {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl From<u32> for Rva {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl TryFrom<Rva> for usize {
    type Error = TryFromIntError;

    fn try_from(value: Rva) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

impl TryFrom<u64> for Rva {
    type Error = TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<usize> for Rva {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

#[allow(non_snake_case)]
mod abi {
    use super::Rva;
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
}

use abi::{
    CompleteObjectLocator,
    TypeDescriptor,
};

struct ImageSection<'image> {
    virtual_address: Rva,
    bytes: &'image [u8],
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

    fn find_iter<T>(&self, value: T) -> impl Iterator<Item = usize> + 'image
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

struct ImageSections<'image> {
    image_base: Va,
    data: ImageSection<'image>,
    rdata: ImageSection<'image>,
}

impl<'image> ImageSections<'image> {
    fn try_locate(pe: &PeFile<'image>) -> anyhow::Result<Self> {
        Ok(Self {
            image_base: pe.optional_header().ImageBase.into(),
            data: ImageSection::try_locate(pe, b".data".into())?,
            rdata: ImageSection::try_locate(pe, b".rdata".into())?,
        })
    }

    fn lookup_type_descriptor_vdtor(&self) -> anyhow::Result<Va> {
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

    fn lookup_vftables(
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

#[derive(Clone, Copy)]
struct StringHandle(usize);

impl StringHandle {
    fn resolve<'type_info>(self, type_info: &'type_info TypeInformation) -> &'type_info str {
        &type_info.undecorated_strings[self.0]
    }
}

impl From<usize> for StringHandle {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

struct TypeDescriptorInfo<'image> {
    rva: Rva,
    decorated_name: &'image BStr,
    undecorated_name: StringHandle,
}

struct ClassInfo<'image> {
    vftables: SmallVec<[Rva; 1]>,
    decorated_name: &'image BStr,
    undecorated_name: StringHandle,
}

struct TypeInformation<'image> {
    undecorated_strings: Vec<String>,
    type_descriptors: Vec<TypeDescriptorInfo<'image>>,
    classes: Vec<ClassInfo<'image>>,
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
        Some(result)
    }

    fn try_scrape(pe: &PeFile<'image>) -> anyhow::Result<Self> {
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

#[derive(Clone, Copy)]
struct Id(u64);

impl From<u64> for Id {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

struct AddressBin {
    mappings: BTreeMap<Rva, Id>,
}

impl AddressBin {
    fn try_parse(address_bin: &Path) -> anyhow::Result<Self> {
        let mut src = File::open(address_bin).context("failed to open address bin")?;
        let mut read_u64 = || {
            src.read_u64::<LittleEndian>()
                .context("error while reading address bin")
        };
        let len = read_u64().context("failed to read len")?;
        let mut mappings = BTreeMap::new();
        for _ in 0..len {
            let id = read_u64().context("failed to read id")?.into();
            let offset = read_u64()
                .context("failed to read offset")?
                .try_into()
                .context("read an offset too large to fit into a u32")?;
            mappings.insert(offset, id);
        }
        Ok(Self { mappings })
    }

    fn get(&self, key: Rva) -> Option<Id> {
        self.mappings.get(&key).copied()
    }
}

fn write_type_descriptors(
    type_info: &TypeInformation,
    address_bin: &AddressBin,
    output_directory: &Path,
) -> anyhow::Result<()> {
    info!("writing type descriptors...");
    let output_file = output_directory.join("RTTI_IDs.h");
    let mut file = File::create(&output_file)
        .with_context(|| format!("failed to create output file: {output_file:?}"))?;
    write!(
        file,
        "#pragma once\n\nnamespace RE\n{{\n\tnamespace RTTI\n\t{{\n"
    )?;

    for type_descriptor in &type_info.type_descriptors {
        let Some(id) = address_bin.get(type_descriptor.rva) else {
            warn!(
                "failed to get id for `RTTI Type Descriptor', with offset {}, for type '{}'",
                type_descriptor.rva,
                type_descriptor.decorated_name.to_str_lossy()
            );
            continue;
        };
        writeln!(
            file,
            "\t\tinline constexpr REL::ID {}{{ {id} }};",
            type_descriptor.undecorated_name.resolve(type_info)
        )?;
    }

    write!(file, "\t}}\n}}\n")?;
    Ok(())
}

fn write_vftables(
    type_info: &TypeInformation,
    address_bin: &AddressBin,
    output_directory: &Path,
) -> anyhow::Result<()> {
    info!("writing vftables...");
    let output_file = output_directory.join("VTABLE_IDs.h");
    let mut file = File::create(&output_file)
        .with_context(|| format!("failed to create output file: {output_file:?}"))?;
    write!(
        file,
        "#pragma once\n\nnamespace RE\n{{\n\tnamespace VTABLE\n\t{{\n"
    )?;

    let mut ids = String::new();
    let mut warnings = (None, 0);
    for class in &type_info.classes {
        macro_rules! get_id {
			($i:expr, $rva:expr) => {{
				let i = $i;
				let rva = $rva;
				match address_bin.get(rva) {
					Some(id) => id,
					None => {
						warnings.1 += 1;
						if warnings.0.is_none() {
							warnings.0 = Some(format!(
								"failed to get id for `vftable' at {{{i}}}, with offset {rva}, for type '{}'",
								class.decorated_name.to_str_lossy()
							));
						}
						continue;
					}
				}
			}}
		}

        ids.clear();
        let (&last, rest) = class
            .vftables
            .split_last()
            .expect("class should have at least 1 vftable");
        for (i, vftable) in rest.iter().enumerate() {
            let id = get_id!(i, *vftable);
            write!(ids, "REL::ID({id}), ")?;
        }
        let id = get_id!(class.vftables.len() - 1, last);
        write!(ids, "REL::ID({id})")?;

        writeln!(
            file,
            "\t\tinline constexpr std::array<REL::ID, {}> {}{{ {ids} }};",
            class.vftables.len(),
            class.undecorated_name.resolve(type_info)
        )?;
    }

    if let Some(warning) = warnings.0 {
        warn!("{warning}");
        let count = warnings.1 - 1;
        if count > 0 {
            warn!("and {count} others...");
        }
    }

    write!(file, "\t}}\n}}\n")?;
    Ok(())
}

pub fn scrape_type_information(
    input_image: &Path,
    address_bin: &Path,
    output_directory: &Path,
) -> anyhow::Result<()> {
    let image = fs::read(input_image)
        .with_context(|| format!("failed to read input file into memory: {input_image:?}"))?;
    let type_info = {
        let pe = PeFile::from_bytes(&image)
            .with_context(|| format!("failed to read input file as a pe file: {input_image:?}"))?;
        TypeInformation::try_scrape(&pe).with_context(|| {
            format!("failed to scrap type information from input file: {input_image:?}")
        })?
    };
    let address_bin = AddressBin::try_parse(address_bin)
        .with_context(|| format!("error while reading address bin: {address_bin:?}"))?;
    write_type_descriptors(&type_info, &address_bin, output_directory)
        .context("failed to write type descriptors")?;
    write_vftables(&type_info, &address_bin, output_directory)
        .context("failed to write vftables")?;
    Ok(())
}
