use bytemuck::{
    AnyBitPattern,
    NoUninit,
};
use std::{
    fmt::{
        self,
        Display,
        Formatter,
    },
    num::TryFromIntError,
};

#[repr(transparent)]
#[derive(AnyBitPattern, Clone, Copy, Eq, NoUninit, Ord, PartialEq, PartialOrd)]
pub(crate) struct Va(u64);

impl Va {
    pub(crate) fn checked_add(self, rhs: Self) -> Option<Self> {
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
pub(crate) struct Rva(u32);

impl Rva {
    pub(crate) fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self::from)
    }

    pub(crate) fn checked_sub(self, rhs: Self) -> Option<Self> {
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
