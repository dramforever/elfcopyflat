#![allow(unused)]

use anyhow::bail;
use std::{
    io::{self, Read, Seek},
    mem::size_of,
};
use zerocopy::*;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Mag(pub [u8; 4]);

impl Mag {
    pub const ELFMAG: Mag = Self([0x7f, b'E', b'L', b'F']);

    pub fn valid(self) -> bool {
        self == Self::ELFMAG
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Class(pub u8);

impl Class {
    pub const ELFCLASSNONE: Self = Self(0);
    pub const ELFCLASS32: Self = Self(1);
    pub const ELFCLASS64: Self = Self(2);

    pub fn valid(self) -> bool {
        self == Self::ELFCLASS32 || self == Self::ELFCLASS64
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Data(pub u8);

impl Data {
    pub const ELFDATANONE: Self = Self(0);
    pub const ELFDATA2LSB: Self = Self(1);
    pub const ELFDATA2MSB: Self = Self(2);

    pub fn valid(self) -> bool {
        self == Self::ELFDATA2LSB || self == Self::ELFDATA2MSB
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Version(pub u8);

impl Version {
    pub const EV_CURRENT: Self = Self(1);

    pub fn valid(self) -> bool {
        self == Self::EV_CURRENT
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct OsAbi(pub u8);

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct AbiVersion(pub u8);

#[derive(Debug, Clone, FromZeroes, FromBytes)]
#[repr(C)]
pub struct Ident {
    magic: [u8; 4],
    class: Class,
    data: Data,
    version: Version,
    os_abi: OsAbi,
    abi_version: AbiVersion,
    pad: [u8; 16 - 9],
}

impl Ident {
    pub const EI_NIDENT: usize = 16;

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.class.valid() {
            bail!("Invalid class")
        }
        if !self.data.valid() {
            bail!("Invalid data (endianness)")
        }
        if !self.version.valid() {
            bail!("Invalid version")
        }

        Ok(())
    }

    pub fn read(mut r: impl Read) -> io::Result<Self> {
        let buf = &mut [0; size_of::<Self>()];
        r.read_exact(buf)?;
        Ok(FromBytes::read_from(buf).unwrap())
    }
}

const _: () = assert!(size_of::<Ident>() == Ident::EI_NIDENT);

#[derive(Debug, Clone, FromZeroes, FromBytes)]
#[repr(C)]
pub struct EhdrN<O: ByteOrder, UN> {
    e_ident: Ident,
    e_type: U16<O>,
    e_machine: U16<O>,
    e_version: U32<O>,
    e_entry: UN,
    e_phoff: UN,
    e_shoff: UN,
    e_flags: U32<O>,
    e_ehsize: U16<O>,
    e_phentsize: U16<O>,
    e_phnum: U16<O>,
    e_shentsize: U16<O>,
    e_shnum: U16<O>,
    e_shstrndx: U16<O>,
}

impl<O: ByteOrder, UN: FromBytes + Into<u64>> EhdrN<O, UN> {
    pub fn wrap<O1: ByteOrder, UN1>(self) -> EhdrN<O1, UN1>
    where
        U32<O1>: From<u32>,
        U16<O1>: From<u16>,
        UN1: From<u64>,
    {
        EhdrN {
            e_ident: self.e_ident,
            e_type: self.e_type.get().into(),
            e_machine: self.e_machine.get().into(),
            e_version: self.e_version.get().into(),
            e_entry: self.e_entry.into().into(),
            e_phoff: self.e_phoff.into().into(),
            e_shoff: self.e_shoff.into().into(),
            e_flags: self.e_flags.get().into(),
            e_ehsize: self.e_ehsize.get().into(),
            e_phentsize: self.e_phentsize.get().into(),
            e_phnum: self.e_phnum.get().into(),
            e_shentsize: self.e_shentsize.get().into(),
            e_shnum: self.e_shnum.get().into(),
            e_shstrndx: self.e_shstrndx.get().into(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.e_ident.validate()?;

        let phentsize = match self.e_ident.class {
            Class::ELFCLASS32 => size_of::<Phdr32<NativeEndian>>(),
            Class::ELFCLASS64 => size_of::<Phdr64<NativeEndian>>(),
            _ => panic!("Invalid ELF header slipped through"),
        };

        if usize::from(self.e_phentsize.get()) != phentsize {
            bail!("Invalid e_phentsize")
        }

        if self.e_phnum.get() == u16::MAX {
            bail!("Too many segments, unimplemented PN_XNUM")
        }

        Ok(())
    }

    fn pipe_validate(self) -> anyhow::Result<Self> {
        self.validate()?;
        Ok(self)
    }

    pub fn read(mut r: impl Read) -> io::Result<Self> {
        // error: constant expression depends on a generic parameter
        // let buf = &mut [0; size_of::<Self>()];

        let buf = &mut [0; size_of::<Ehdr64<NativeEndian>>()][..size_of::<Self>()];
        r.read_exact(buf)?;
        Ok(FromBytes::read_from(buf).unwrap())
    }
}

pub type Ehdr32<O> = EhdrN<O, U32<O>>;
pub type Ehdr64<O> = EhdrN<O, U64<O>>;

#[derive(Debug, Clone)]
pub struct Ehdr(pub EhdrN<NativeEndian, U64<NativeEndian>>);

impl Ehdr {
    pub fn read(mut r: impl Read + Seek) -> anyhow::Result<Self> {
        let pos = r.stream_position()?;
        let ident = Ident::read(&mut r)?;
        r.seek(io::SeekFrom::Start(pos))?;
        let res = match (ident.class, ident.data) {
            (Class::ELFCLASS32, Data::ELFDATA2LSB) => {
                <Ehdr32<LittleEndian>>::read(r)?.pipe_validate()?.wrap()
            }
            (Class::ELFCLASS64, Data::ELFDATA2LSB) => {
                <Ehdr64<LittleEndian>>::read(r)?.pipe_validate()?.wrap()
            }
            (Class::ELFCLASS32, Data::ELFDATA2MSB) => {
                <Ehdr32<BigEndian>>::read(r)?.pipe_validate()?.wrap()
            }
            (Class::ELFCLASS64, Data::ELFDATA2MSB) => {
                <Ehdr64<BigEndian>>::read(r)?.pipe_validate()?.wrap()
            }
            _ => panic!("Invalid ELF header slipped through"),
        };
        Ok(Self(res))
    }

    pub fn ph_offset(&self) -> u64 {
        self.0.e_phoff.get()
    }

    pub fn ph_entry_size(&self) -> usize {
        usize::from(self.0.e_phentsize.get())
    }

    pub fn ph_size(&self) -> usize {
        self.ph_entry_size() * usize::from(self.0.e_phnum.get())
    }
}

#[derive(Debug, Clone, FromZeroes, FromBytes)]
#[repr(C)]
pub struct Phdr32<O: ByteOrder> {
    p_type: U32<O>,
    p_offset: U32<O>,
    p_vaddr: U32<O>,
    p_paddr: U32<O>,
    p_filesz: U32<O>,
    p_memsz: U32<O>,
    p_flags: U32<O>,
    p_align: U32<O>,
}

impl<O: ByteOrder> Phdr32<O> {
    pub fn wrap<O1: ByteOrder>(self) -> Phdr64<O1> {
        let up = |x: u32| -> u64 { x.into() };
        Phdr64 {
            p_type: self.p_type.get().into(),
            p_flags: self.p_flags.get().into(),
            p_offset: up(self.p_offset.get()).into(),
            p_vaddr: up(self.p_vaddr.get()).into(),
            p_paddr: up(self.p_paddr.get()).into(),
            p_filesz: up(self.p_filesz.get()).into(),
            p_memsz: up(self.p_memsz.get()).into(),
            p_align: up(self.p_align.get()).into(),
        }
    }
}

#[derive(Debug, Clone, FromZeroes, FromBytes)]
#[repr(C)]
pub struct Phdr64<O: ByteOrder> {
    p_type: U32<O>,
    p_flags: U32<O>,
    p_offset: U64<O>,
    p_vaddr: U64<O>,
    p_paddr: U64<O>,
    p_filesz: U64<O>,
    p_memsz: U64<O>,
    p_align: U64<O>,
}

impl<O: ByteOrder> Phdr64<O> {
    pub fn wrap<O1: ByteOrder>(self) -> Phdr64<O1> {
        Phdr64 {
            p_type: self.p_type.get().into(),
            p_flags: self.p_flags.get().into(),
            p_offset: self.p_offset.get().into(),
            p_vaddr: self.p_vaddr.get().into(),
            p_paddr: self.p_paddr.get().into(),
            p_filesz: self.p_filesz.get().into(),
            p_memsz: self.p_memsz.get().into(),
            p_align: self.p_align.get().into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Type(pub u32);

impl Type {
    pub const PT_LOAD: Self = Self(1);
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, FromZeroes, FromBytes)]
#[repr(transparent)]
pub struct Flags(pub u32);

impl Flags {
    pub const PF_X: Self = Self(1 << 0);
    pub const PF_W: Self = Self(1 << 1);
    pub const PF_R: Self = Self(1 << 2);

    pub fn executable(self) -> bool {
        self.0 & Self::PF_X.0 != 0
    }
    pub fn writable(self) -> bool {
        self.0 & Self::PF_W.0 != 0
    }
    pub fn readable(self) -> bool {
        self.0 & Self::PF_R.0 != 0
    }
}

#[derive(Debug, Clone)]
pub struct Phdr(pub Phdr64<NativeEndian>);

impl Phdr {
    pub fn from_bytes(data: &[u8], ehdr: &Ehdr) -> Self {
        let res = match (ehdr.0.e_ident.class, ehdr.0.e_ident.data) {
            (Class::ELFCLASS32, Data::ELFDATA2LSB) => <Phdr32<LittleEndian>>::read_from(data)
                .expect("Invalid ELF header slipped through")
                .wrap(),
            (Class::ELFCLASS64, Data::ELFDATA2LSB) => <Phdr64<LittleEndian>>::read_from(data)
                .expect("Invalid ELF header slipped through")
                .wrap(),
            (Class::ELFCLASS32, Data::ELFDATA2MSB) => <Phdr32<BigEndian>>::read_from(data)
                .expect("Invalid ELF header slipped through")
                .wrap(),
            (Class::ELFCLASS64, Data::ELFDATA2MSB) => <Phdr64<BigEndian>>::read_from(data)
                .expect("Invalid ELF header slipped through")
                .wrap(),
            _ => panic!("Invalid ELF header slipped through"),
        };

        Self(res)
    }

    pub fn to_type(&self) -> Type {
        Type(self.0.p_type.get())
    }

    pub fn flags(&self) -> Flags {
        Flags(self.0.p_flags.get())
    }

    pub fn address(&self) -> u64 {
        self.0.p_vaddr.get()
    }

    pub fn file_offset(&self) -> u64 {
        self.0.p_offset.get()
    }

    pub fn file_size(&self) -> u64 {
        self.0.p_filesz.get()
    }

    pub fn memory_size(&self) -> u64 {
        self.0.p_memsz.get()
    }
}
