use crate::primitives::Rva;
use anyhow::Context as _;
use byteorder::{
    LittleEndian,
    ReadBytesExt as _,
};
use std::{
    collections::BTreeMap,
    fmt::{
        self,
        Display,
        Formatter,
    },
    fs::File,
    path::Path,
};

#[derive(Clone, Copy)]
pub(crate) struct Id(u64);

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

pub(crate) struct AddressBin {
    mappings: BTreeMap<Rva, Id>,
}

impl AddressBin {
    pub(crate) fn try_parse(address_bin: &Path) -> anyhow::Result<Self> {
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

    pub(crate) fn get(&self, key: Rva) -> Option<Id> {
        self.mappings.get(&key).copied()
    }
}
