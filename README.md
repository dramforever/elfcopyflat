# `elfcopyflat`

Copy loadable segments in an ELF file to a flat binary

## Basic usage

Copy all segments:

```
elfcopyflat program.elf program.bin
```

Separate read-only and read-write segments:

```
elfcopyflat --if-not w program.elf program-ro.bin
elfcopyflat --if w program.elf program-rw.bin
```

## Difference from `objcopy` from binutils

`elfcopyflat` copies segments, while `objcopy` copies sections.

The most prominent difference is that if your ELF file is linked so that the ELF
file header and program headers are actually supposed to be loaded,
`elfcopyflat` will keep the headers whereas `objcopy` will throw them away
because they're not part of a section. This is the case for all usual ELF
binaries for Unix-like operating systems.

Also, if your ELF file has been stripped of section headers, `objcopy` will give
up and not copy anything. Such a binary can definitely still be loaded and run
though, and `elfcopyflat` will happily use the segment information to seek out
what to copy.

Oh and `elfcopyflat` only has ELF input and flat binary output.
