#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

mod abi;
mod addrlib;
mod image;
mod logging;
mod primitives;
mod rtti;

use crate::{
    addrlib::AddressBin,
    rtti::TypeInformation,
};
use anyhow::Context as _;
use bstr::ByteSlice as _;
use log::{
    info,
    warn,
};
use logging::Spammable;
use pelite::pe64::PeFile;
use std::{
    fmt::Write as _,
    fs::{
        self,
        File,
    },
    io::Write as _,
    path::Path,
};

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
    let mut warnings = Spammable::new(
        "this is probably because the meh's tools did not generate ids for these addresses",
    );
    for class in &type_info.classes {
        macro_rules! get_id {
            ($i:expr, $rva:expr) => {{
                let i = $i;
                let rva = $rva;
                match address_bin.get(rva) {
                    Some(id) => id,
                    None => {
                        warnings.warn(|| {
                            format!(
                                "failed to get id for `vftable' at {{{i}}}, with offset {rva}, for type '{}'",
                                class.decorated_name.to_str_lossy()
                            )
                        });
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
