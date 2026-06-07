import { writeFileSync } from 'fs'

// Minimal valid ELF64 x86_64 with a .text section containing recognizable instructions.
// Layout: [ELF header | program header | .text bytes | section headers | shstrtab]

const textCode = new Uint8Array([
  0x55,                               // push rbp
  0x48, 0x89, 0xe5,                   // mov  rbp, rsp
  0xb8, 0x2a, 0x00, 0x00, 0x00,       // mov  eax, 42         ; the answer
  0x48, 0x83, 0xc0, 0x01,             // add  rax, 1
  0xe8, 0x10, 0x00, 0x00, 0x00,       // call +0x10           ; call something
  0x90, 0x90, 0x90,                   // nop nop nop
  0x5d,                               // pop  rbp
  0xc3,                               // ret
  0xcc, 0xcc, 0xcc, 0xcc,             // int3 padding
  // hidden ascii: a juicy string the analyst should find
  0x48,0x65,0x6c,0x6c,0x6f,0x20,0x66,0x72,0x6f,0x6d,0x20,0x42,0x69,0x6e,0x53,0x63,0x6f,0x70,0x65,0x21,0x00,
  0x73,0x65,0x63,0x72,0x65,0x74,0x5f,0x66,0x6c,0x61,0x67,0x7b,0x77,0x33,0x62,0x5f,0x72,0x33,0x76,0x33,0x72,0x73,0x33,0x7d,0x00,
])

const shstrtab = Buffer.from('\0.shstrtab\0.text\0', 'ascii')

const EH_SIZE = 64
const PH_SIZE = 56
const SH_SIZE = 64
const NUM_SECT = 3 // null, .text, .shstrtab

const textOff = EH_SIZE + PH_SIZE
const shstrtabOff = textOff + textCode.length
const sectionHeadersOff = shstrtabOff + shstrtab.length

const total = sectionHeadersOff + NUM_SECT * SH_SIZE
const buf = Buffer.alloc(total)

// ---- ELF header ----
buf.write('\x7fELF', 0, 'binary')
buf[4] = 2 // 64-bit
buf[5] = 1 // little-endian
buf[6] = 1 // EI_VERSION
buf[7] = 0
// e_type = ET_EXEC(2)
buf.writeUInt16LE(2, 16)
// e_machine = EM_X86_64(0x3e)
buf.writeUInt16LE(0x3e, 18)
// e_version
buf.writeUInt32LE(1, 20)
// e_entry
buf.writeBigUInt64LE(BigInt(0x400000 + textOff), 24)
// e_phoff
buf.writeBigUInt64LE(BigInt(EH_SIZE), 32)
// e_shoff
buf.writeBigUInt64LE(BigInt(sectionHeadersOff), 40)
// e_flags
buf.writeUInt32LE(0, 48)
// e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
buf.writeUInt16LE(EH_SIZE, 52)
buf.writeUInt16LE(PH_SIZE, 54)
buf.writeUInt16LE(1, 56)
buf.writeUInt16LE(SH_SIZE, 58)
buf.writeUInt16LE(NUM_SECT, 60)
buf.writeUInt16LE(2, 62) // shstrtab index

// ---- Program header (PT_LOAD) ----
const phOff = EH_SIZE
buf.writeUInt32LE(1, phOff + 0)        // p_type = PT_LOAD
buf.writeUInt32LE(5, phOff + 4)        // p_flags = R+X
buf.writeBigUInt64LE(BigInt(0), phOff + 8)            // p_offset
buf.writeBigUInt64LE(BigInt(0x400000), phOff + 16)    // p_vaddr
buf.writeBigUInt64LE(BigInt(0x400000), phOff + 24)    // p_paddr
buf.writeBigUInt64LE(BigInt(total), phOff + 32)       // p_filesz
buf.writeBigUInt64LE(BigInt(total), phOff + 40)       // p_memsz
buf.writeBigUInt64LE(BigInt(0x1000), phOff + 48)      // p_align

// ---- .text bytes ----
buf.set(textCode, textOff)
// ---- shstrtab ----
shstrtab.copy(buf, shstrtabOff)

// ---- Section headers ----
function writeSh(idx: number, nameOff: number, type: number, flags: number,
                  addr: number, off: number, size: number) {
  const o = sectionHeadersOff + idx * SH_SIZE
  buf.writeUInt32LE(nameOff, o + 0)
  buf.writeUInt32LE(type, o + 4)
  buf.writeBigUInt64LE(BigInt(flags), o + 8)
  buf.writeBigUInt64LE(BigInt(addr), o + 16)
  buf.writeBigUInt64LE(BigInt(off), o + 24)
  buf.writeBigUInt64LE(BigInt(size), o + 32)
  buf.writeUInt32LE(0, o + 40) // link
  buf.writeUInt32LE(0, o + 44) // info
  buf.writeBigUInt64LE(BigInt(1), o + 48) // addralign
  buf.writeBigUInt64LE(BigInt(0), o + 56) // entsize
}

// Section 0 = NULL
writeSh(0, 0, 0, 0, 0, 0, 0)
// Section 1 = .text  (name offset 11 in shstrtab: "\0.shstrtab\0.text\0")
writeSh(1, 11, 1 /*PROGBITS*/, 0x6 /*ALLOC|EXEC*/, 0x400000 + textOff, textOff, textCode.length)
// Section 2 = .shstrtab (name offset 1)
writeSh(2, 1, 3 /*STRTAB*/, 0, 0, shstrtabOff, shstrtab.length)

writeFileSync('hello.bin', buf)
console.log('Wrote hello.bin —', buf.length, 'bytes')
