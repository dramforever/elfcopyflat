use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use anyhow::bail;
use clap::Parser;
use clap_num::maybe_hex;
use elf::Phdr;

mod elf;

/// elfcopyflat: Copy loadable segments in an ELF file to a flat binary
#[derive(Debug, Parser)]
struct Args {
    /// Only copy segments with these flags (among "rwx")
    #[arg(long, value_name = "FLAGS", value_parser=parse_flags)]
    if_: Option<u32>,

    /// Only copy segments without these flags (among "rwx")
    #[arg(long, value_name = "FLAGS", value_parser=parse_flags)]
    if_not: Option<u32>,

    /// Address to start flat binary at (Defaults to lowest address among segments)
    #[arg(long, value_name = "ADDRESS", value_parser=maybe_hex::<u64>)]
    base: Option<u64>,

    /// Allow overlapping segments
    #[arg(long)]
    allow_overlaps: bool,

    /// Print more information
    #[arg(long, short)]
    verbose: bool,

    /// Input ELF file
    input: OsString,

    /// Output flat binary
    output: OsString,
}

fn parse_flags(s: &str) -> Result<u32, String> {
    let mut flags = 0;
    for c in s.chars() {
        let val = match c {
            'r' | 'R' => elf::Flags::PF_R.0,
            'w' | 'W' => elf::Flags::PF_W.0,
            'x' | 'X' => elf::Flags::PF_X.0,
            _ => return Err(format!("Unknown flag '{c}'")),
        };

        if flags & val != 0 {
            return Err(format!("Duplicate flag '{}'", c.to_ascii_lowercase()));
        } else {
            flags |= val;
        }
    }
    Ok(flags)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut input_file = File::open(&args.input)?;
    let mut output_file = File::create(&args.output)?;

    let ehdr = elf::Ehdr::read(&mut input_file)?;
    let mut phdr_bytes: Vec<u8> = vec![0; ehdr.ph_size()];
    input_file.seek(SeekFrom::Start(ehdr.ph_offset()))?;
    input_file.read_exact(&mut phdr_bytes)?;

    let mut phdrs: Vec<elf::Phdr> = phdr_bytes
        .chunks_exact(ehdr.ph_entry_size())
        .map(|b| Phdr::from_bytes(b, &ehdr))
        .filter(|phdr| {
            phdr.to_type() == elf::Type::PT_LOAD
                && phdr.flags().0 & args.if_.unwrap_or(!0) != 0
                && phdr.flags().0 & args.if_not.unwrap_or(0) == 0
        })
        .collect();

    phdrs.sort_by_key(|p| p.address());

    if args.verbose {
        eprintln!("Segments in file to copy:");
        for p in &phdrs {
            let r = if p.flags().readable() { "r" } else { "-" };
            let w = if p.flags().writable() { "w" } else { "-" };
            let x = if p.flags().executable() { "x" } else { "-" };
            eprintln!(
                "  {r}{w}{x} {offset:#x} + {filesz:#x} bytes in file, {addr:#x} + {memsz:#x} bytes in memory",
                offset = p.file_offset(),
                filesz = p.file_size(),
                addr = p.address(),
                memsz = p.memory_size(),
            );
        }
    }

    let overlaps = phdrs
        .iter()
        .zip(phdrs.iter().skip(1))
        .filter(|(pa, pb)| {
            if pa.address() + pa.memory_size() > pb.address() {
                eprintln!(
                    "Segment at {start:#x} has size {size:#x}, which overlaps the next segment at {next:#x}",
                    start = pa.address(),
                    size = pa.memory_size(),
                    next = pb.address(),
                );
                true
            } else {
                false
            }
        })
        .count();

    if overlaps > 0 && !args.allow_overlaps {
        bail!("Overlapping segments (Use --allow-overlaps to use it anyway)")
    }

    let base = args
        .base
        .unwrap_or_else(|| phdrs.iter().map(|phdr| phdr.address()).min().unwrap_or(0));

    if args.verbose {
        eprintln!("Base address {base:#x}")
    }

    for p in &phdrs {
        output_file.seek(SeekFrom::Start(p.address() - base))?;
        input_file.seek(SeekFrom::Start(p.file_offset()))?;
        std::io::copy(&mut (&mut input_file).take(p.file_size()), &mut output_file)?;
    }

    Ok(())
}
