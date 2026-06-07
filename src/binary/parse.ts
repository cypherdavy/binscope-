export type BinaryFormat =
  | 'PE' | 'PE/.NET' | 'ELF' | 'Mach-O' | 'Mach-O/FAT'
  | 'WASM' | 'Java' | 'DEX' | 'Python/pyc' | 'AR' | 'ZIP/JAR/APK'
  | 'Raw' | 'Unknown'

export type Arch =
  | 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'riscv'
  | 'wasm' | 'dalvik' | 'jvm' | 'cil' | 'python' | 'unknown'

export interface Section {
  name: string
  vaddr: number
  size: number
  fileOffset: number
  flags: string
}

export interface ImportInfo {
  library?: string
  name: string
  ordinal?: number
}

export interface ParsedBinary {
  format: BinaryFormat
  arch: Arch
  bits: 32 | 64
  entryPoint: number
  sections: Section[]
  imports: ImportInfo[]
  exports: string[]
  data: Uint8Array
  textSection?: Section
  meta: Record<string, string | number>
}

function u16(d: DataView, o: number, le = true) { return d.getUint16(o, le) }
function u32(d: DataView, o: number, le = true) { return d.getUint32(o, le) }
function u64(d: DataView, o: number, le = true) {
  const lo = d.getUint32(o, le)
  const hi = d.getUint32(o + 4, le)
  return le ? hi * 0x100000000 + lo : lo * 0x100000000 + hi
}
function readCString(data: Uint8Array, off: number, max = 256): string {
  let s = ''
  for (let i = 0; i < max && off + i < data.length && data[off + i] !== 0; i++) {
    s += String.fromCharCode(data[off + i])
  }
  return s
}

export function detectFormat(data: Uint8Array): BinaryFormat {
  if (data.length < 4) return 'Unknown'
  // PE
  if (data[0] === 0x4d && data[1] === 0x5a) return 'PE'
  // ELF
  if (data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) return 'ELF'
  // Mach-O / FAT
  const m = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
  if (m === 0xcafebabe || m === 0xbebafeca || m === 0xcafebabf) return 'Mach-O/FAT'
  if (m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe) return 'Mach-O'
  // WASM
  if (data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d) return 'WASM'
  // Java .class
  if (data[0] === 0xca && data[1] === 0xfe && data[2] === 0xba && data[3] === 0xbe) return 'Java'
  // DEX
  if (data[0] === 0x64 && data[1] === 0x65 && data[2] === 0x78 && data[3] === 0x0a) return 'DEX'
  // Python pyc (multiple magics over years, check 3rd+4th = 0x0d 0x0a)
  if (data[2] === 0x0d && data[3] === 0x0a && data.length > 16) return 'Python/pyc'
  // ZIP / JAR / APK
  if (data[0] === 0x50 && data[1] === 0x4b && (data[2] === 0x03 || data[2] === 0x05)) return 'ZIP/JAR/APK'
  // ar archive (.a / .deb)
  if (data[0] === 0x21 && data[1] === 0x3c && data[2] === 0x61 && data[3] === 0x72) return 'AR'
  return 'Raw'
}

// ────────────────────────────────────────────────────────────
// ELF
// ────────────────────────────────────────────────────────────
function parseELF(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const bits = data[4] === 2 ? 64 : 32
  const le = data[5] === 1
  const machine = u16(d, 18, le)
  let arch: Arch = 'unknown'
  if (machine === 0x3e) arch = 'x64'
  else if (machine === 0x03) arch = 'x86'
  else if (machine === 0xb7) arch = 'arm64'
  else if (machine === 0x28) arch = 'arm'
  else if (machine === 0x08) arch = 'mips'
  else if (machine === 0xf3) arch = 'riscv'

  const entry = bits === 64 ? u64(d, 24, le) : u32(d, 24, le)
  const shoff = bits === 64 ? u64(d, 40, le) : u32(d, 32, le)
  const shentsize = bits === 64 ? u16(d, 58, le) : u16(d, 46, le)
  const shnum = bits === 64 ? u16(d, 60, le) : u16(d, 48, le)
  const shstrndx = bits === 64 ? u16(d, 62, le) : u16(d, 50, le)

  const sections: Section[] = []
  let strTab: Uint8Array | null = null
  if (shstrndx < shnum) {
    const stOff = shoff + shstrndx * shentsize
    const offField = bits === 64 ? u64(d, stOff + 24, le) : u32(d, stOff + 16, le)
    const sizeField = bits === 64 ? u64(d, stOff + 32, le) : u32(d, stOff + 20, le)
    strTab = data.slice(offField, offField + sizeField)
  }

  let dynsymOff = 0, dynsymSize = 0, dynstrOff = 0, dynstrSize = 0, dynsymEnt = bits === 64 ? 24 : 16
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize
    const nameOff = u32(d, o, le)
    const type = u32(d, o + 4, le)
    const flags = bits === 64 ? u64(d, o + 8, le) : u32(d, o + 8, le)
    const vaddr = bits === 64 ? u64(d, o + 16, le) : u32(d, o + 12, le)
    const fileOff = bits === 64 ? u64(d, o + 24, le) : u32(d, o + 16, le)
    const size = bits === 64 ? u64(d, o + 32, le) : u32(d, o + 20, le)
    const name = strTab ? readCString(strTab, nameOff) : ''
    const f: string[] = []
    if (flags & 0x2) f.push('A')
    if (flags & 0x4) f.push('X')
    if (flags & 0x1) f.push('W')
    sections.push({ name, vaddr, size, fileOffset: fileOff, flags: f.join('') })
    if (name === '.dynsym') { dynsymOff = fileOff; dynsymSize = size }
    if (name === '.dynstr') { dynstrOff = fileOff; dynstrSize = size }
    if (type === 11) dynsymEnt = bits === 64 ? 24 : 16
  }

  const imports: ImportInfo[] = []
  const exports: string[] = []
  if (dynsymOff && dynstrOff) {
    const dynstr = data.slice(dynstrOff, dynstrOff + dynstrSize)
    const count = Math.floor(dynsymSize / dynsymEnt)
    for (let i = 1; i < count && imports.length + exports.length < 2000; i++) {
      const so = dynsymOff + i * dynsymEnt
      const nameIdx = u32(d, so, le)
      const symValue = bits === 64 ? u64(d, so + 8, le) : u32(d, so + 4, le)
      const symShndx = bits === 64 ? u16(d, so + 6, le) : u16(d, so + 14, le)
      const name = readCString(dynstr, nameIdx)
      if (!name) continue
      if (symShndx === 0 || symValue === 0) imports.push({ name })
      else exports.push(name)
    }
  }

  const textSection = sections.find(s => s.name === '.text') || sections.find(s => s.flags.includes('X'))
  return {
    format: 'ELF', arch, bits: bits as 32 | 64, entryPoint: entry,
    sections, imports, exports, data, textSection,
    meta: { 'endian': le ? 'little' : 'big', 'machine': '0x' + machine.toString(16) }
  }
}

// ────────────────────────────────────────────────────────────
// PE / PE+ / .NET
// ────────────────────────────────────────────────────────────
function parsePE(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const peOff = u32(d, 0x3c)
  const machine = u16(d, peOff + 4)
  const numSections = u16(d, peOff + 6)
  const timestamp = u32(d, peOff + 8)
  const optHeaderSize = u16(d, peOff + 20)
  const characteristics = u16(d, peOff + 22)
  const optHeaderOff = peOff + 24
  const magic = u16(d, optHeaderOff)
  const bits = magic === 0x20b ? 64 : 32
  let arch: Arch = 'unknown'
  if (machine === 0x8664) arch = 'x64'
  else if (machine === 0x14c) arch = 'x86'
  else if (machine === 0xaa64) arch = 'arm64'
  else if (machine === 0x1c0 || machine === 0x1c4) arch = 'arm'

  const entryRVA = u32(d, optHeaderOff + 16)
  const imageBase = bits === 64 ? u64(d, optHeaderOff + 24) : u32(d, optHeaderOff + 28)
  const dirOffset = optHeaderOff + (bits === 64 ? 112 : 96)
  const importDirRVA = u32(d, dirOffset + 8)
  const importDirSize = u32(d, dirOffset + 12)
  const exportDirRVA = u32(d, dirOffset + 0)
  const comDescriptorRVA = u32(d, dirOffset + 14 * 8) // CLR header — indicates .NET

  const sectionsOff = optHeaderOff + optHeaderSize
  const sections: Section[] = []
  for (let i = 0; i < numSections; i++) {
    const o = sectionsOff + i * 40
    let name = ''
    for (let j = 0; j < 8 && data[o + j] !== 0; j++) name += String.fromCharCode(data[o + j])
    const vsize = u32(d, o + 8)
    const vaddr = u32(d, o + 12) + imageBase
    const rawSize = u32(d, o + 16)
    const rawOff = u32(d, o + 20)
    const chars = u32(d, o + 36)
    const f: string[] = []
    if (chars & 0x20000000) f.push('X')
    if (chars & 0x40000000) f.push('R')
    if (chars & 0x80000000) f.push('W')
    sections.push({ name, vaddr, size: Math.max(vsize, rawSize), fileOffset: rawOff, flags: f.join('') })
  }

  function rvaToFile(rva: number) {
    for (const s of sections) {
      const sectRva = s.vaddr - imageBase
      if (rva >= sectRva && rva < sectRva + s.size) return s.fileOffset + (rva - sectRva)
    }
    return -1
  }

  const imports: ImportInfo[] = []
  if (importDirRVA && importDirSize) {
    let off = rvaToFile(importDirRVA)
    if (off > 0) {
      for (let i = 0; i < 200; i++) {
        const ilt = u32(d, off + 0)
        const nameRVA = u32(d, off + 12)
        const iat = u32(d, off + 16)
        if (ilt === 0 && nameRVA === 0 && iat === 0) break
        const libOff = rvaToFile(nameRVA)
        const lib = libOff > 0 ? readCString(data, libOff, 128) : '?'
        let thunkOff = rvaToFile(ilt || iat)
        if (thunkOff > 0) {
          for (let j = 0; j < 2000; j++) {
            const t = bits === 64 ? u64(d, thunkOff) : u32(d, thunkOff)
            if (!t) break
            const highBit = bits === 64 ? 0x8000000000000000 : 0x80000000
            if (t & highBit) {
              imports.push({ library: lib, name: `Ordinal ${t & 0xffff}`, ordinal: Number(t) & 0xffff })
            } else {
              const hintOff = rvaToFile(Number(t))
              if (hintOff > 0) imports.push({ library: lib, name: readCString(data, hintOff + 2, 128) })
            }
            thunkOff += bits === 64 ? 8 : 4
            if (imports.length > 2000) break
          }
        }
        off += 20
        if (imports.length > 2000) break
      }
    }
  }

  const exports: string[] = []
  if (exportDirRVA) {
    const exOff = rvaToFile(exportDirRVA)
    if (exOff > 0) {
      const nNames = u32(d, exOff + 24)
      const namesRVA = u32(d, exOff + 32)
      const namesOff = rvaToFile(namesRVA)
      if (namesOff > 0) {
        for (let i = 0; i < nNames && i < 1000; i++) {
          const r = u32(d, namesOff + i * 4)
          const o = rvaToFile(r)
          if (o > 0) exports.push(readCString(data, o, 128))
        }
      }
    }
  }

  const isDotNet = comDescriptorRVA !== 0
  const textSection = sections.find(s => s.name === '.text') || sections.find(s => s.flags.includes('X'))
  return {
    format: isDotNet ? 'PE/.NET' : 'PE',
    arch: isDotNet ? 'cil' : arch,
    bits: bits as 32 | 64,
    entryPoint: entryRVA + imageBase,
    sections, imports, exports, data, textSection,
    meta: {
      'compiled': new Date(timestamp * 1000).toISOString(),
      'characteristics': '0x' + characteristics.toString(16),
      'imageBase': '0x' + imageBase.toString(16),
      'subsystem': u16(d, optHeaderOff + 68).toString()
    }
  }
}

// ────────────────────────────────────────────────────────────
// Mach-O (single + FAT)
// ────────────────────────────────────────────────────────────
function parseMachO(data: Uint8Array, fatOffset = 0): ParsedBinary {
  const view = data.subarray(fatOffset)
  const d = new DataView(view.buffer, view.byteOffset, view.byteLength)
  const magic = u32(d, 0, true)
  const bits = (magic === 0xfeedfacf || magic === 0xcffaedfe) ? 64 : 32
  const cputype = u32(d, 4, true)
  let arch: Arch = 'unknown'
  if (cputype === 0x01000007) arch = 'x64'
  else if (cputype === 0x7) arch = 'x86'
  else if (cputype === 0x0100000c) arch = 'arm64'
  else if (cputype === 0xc) arch = 'arm'

  const ncmds = u32(d, 16, true)
  let off = bits === 64 ? 32 : 28
  const sections: Section[] = []
  const imports: ImportInfo[] = []
  let entry = 0
  for (let i = 0; i < ncmds; i++) {
    const cmd = u32(d, off, true)
    const size = u32(d, off + 4, true)
    if (cmd === 0x19 || cmd === 0x1) {
      let segName = ''
      for (let j = 0; j < 16 && view[off + 8 + j] !== 0; j++) segName += String.fromCharCode(view[off + 8 + j])
      const nsects = bits === 64 ? u32(d, off + 64, true) : u32(d, off + 48, true)
      const sectStart = off + (bits === 64 ? 72 : 56)
      const sectSize = bits === 64 ? 80 : 68
      for (let j = 0; j < nsects; j++) {
        const so = sectStart + j * sectSize
        let sname = ''
        for (let k = 0; k < 16 && view[so + k] !== 0; k++) sname += String.fromCharCode(view[so + k])
        const vaddr = bits === 64 ? u64(d, so + 32, true) : u32(d, so + 32, true)
        const ssize = bits === 64 ? u64(d, so + 40, true) : u32(d, so + 36, true)
        const fo = bits === 64 ? u32(d, so + 48, true) : u32(d, so + 40, true)
        sections.push({ name: `${segName}.${sname}`, vaddr, size: ssize, fileOffset: fo + fatOffset, flags: 'X' })
      }
    } else if (cmd === 0x0c || cmd === 0x18) {
      // LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
      const nameOff = u32(d, off + 8, true)
      const lib = readCString(view, off + nameOff, 256)
      imports.push({ library: lib, name: '(dylib)' })
    } else if (cmd === 0x80000028) {
      entry = bits === 64 ? u64(d, off + 8, true) : u32(d, off + 8, true)
    }
    off += size
  }
  const textSection = sections.find(s => s.name.includes('__text')) || sections[0]
  if (!entry && textSection) entry = textSection.vaddr
  return {
    format: 'Mach-O', arch, bits: bits as 32 | 64, entryPoint: entry,
    sections, imports, exports: [], data, textSection,
    meta: { 'cputype': '0x' + cputype.toString(16), 'ncmds': ncmds }
  }
}

function parseFatMachO(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const nfat = u32(d, 4, false)
  const sections: Section[] = []
  let firstOffset = 0
  for (let i = 0; i < nfat && i < 16; i++) {
    const o = 8 + i * 20
    const cpu = u32(d, o, false)
    const offset = u32(d, o + 8, false)
    const size = u32(d, o + 12, false)
    sections.push({ name: `slice_${cpu.toString(16)}`, vaddr: offset, size, fileOffset: offset, flags: 'X' })
    if (i === 0) firstOffset = offset
  }
  if (firstOffset) {
    const inner = parseMachO(data, firstOffset)
    return {
      ...inner,
      format: 'Mach-O/FAT',
      sections: [...sections, ...inner.sections],
      meta: { ...inner.meta, 'fatSlices': nfat }
    }
  }
  return { format: 'Mach-O/FAT', arch: 'unknown', bits: 64, entryPoint: 0, sections, imports: [], exports: [], data, meta: { 'fatSlices': nfat } }
}

// ────────────────────────────────────────────────────────────
// WASM
// ────────────────────────────────────────────────────────────
function parseWASM(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const version = u32(d, 4, true)
  const sections: Section[] = []
  const imports: ImportInfo[] = []
  const exports: string[] = []
  const SECTION_NAMES = ['custom','type','import','function','table','memory','global','export','start','element','code','data','datacount']

  let off = 8
  function readLEB(): number {
    let r = 0, s = 0, b
    do {
      if (off >= data.length) return r
      b = data[off++]
      r |= (b & 0x7f) << s
      s += 7
    } while (b & 0x80)
    return r >>> 0
  }
  function readName(): string {
    const len = readLEB()
    let s = ''
    for (let i = 0; i < len; i++) s += String.fromCharCode(data[off + i])
    off += len
    return s
  }

  while (off < data.length) {
    const sectionStart = off
    const id = data[off++]
    const len = readLEB()
    const bodyStart = off
    const name = SECTION_NAMES[id] || `id_${id}`
    sections.push({ name, vaddr: sectionStart, size: len + (bodyStart - sectionStart), fileOffset: sectionStart, flags: id === 10 ? 'X' : 'R' })
    if (id === 2) {
      const n = readLEB()
      for (let i = 0; i < n && imports.length < 500; i++) {
        const mod = readName()
        const fld = readName()
        const kind = data[off++]
        if (kind === 0) readLEB()
        else { off += 1; readLEB(); if (kind === 1 || kind === 2) readLEB() }
        imports.push({ library: mod, name: fld })
      }
    } else if (id === 7) {
      const n = readLEB()
      for (let i = 0; i < n && exports.length < 500; i++) {
        exports.push(readName())
        off++ // kind
        readLEB() // index
      }
    }
    off = bodyStart + len
  }

  const code = sections.find(s => s.name === 'code')
  return {
    format: 'WASM', arch: 'wasm', bits: 32, entryPoint: code?.fileOffset || 0,
    sections, imports, exports, data, textSection: code,
    meta: { 'version': version, 'sections': sections.length }
  }
}

// ────────────────────────────────────────────────────────────
// Java .class
// ────────────────────────────────────────────────────────────
function parseJava(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const minor = u16(d, 4, false)
  const major = u16(d, 6, false)
  // Walk constant pool
  const cpCount = u16(d, 8, false)
  let off = 10
  const utf8: Record<number, string> = {}
  const classRef: Record<number, number> = {}
  for (let i = 1; i < cpCount; i++) {
    const tag = data[off++]
    switch (tag) {
      case 1: {
        const len = u16(d, off, false); off += 2
        let s = ''
        for (let j = 0; j < len; j++) s += String.fromCharCode(data[off + j])
        off += len
        utf8[i] = s
        break
      }
      case 3: case 4: off += 4; break
      case 5: case 6: off += 8; i++; break
      case 7: classRef[i] = u16(d, off, false); off += 2; break
      case 8: off += 2; break
      case 9: case 10: case 11: case 12: off += 4; break
      case 15: off += 3; break
      case 16: case 19: case 20: off += 2; break
      case 17: case 18: off += 4; break
      default: off += 2
    }
  }
  off += 2 // access_flags
  const thisClass = u16(d, off, false); off += 2
  const className = utf8[classRef[thisClass]] || '?'
  const exports = Object.values(utf8).filter(s => /^[A-Za-z_$][\w$/<>]+$/.test(s)).slice(0, 500)
  return {
    format: 'Java', arch: 'jvm', bits: 32, entryPoint: 0,
    sections: [{ name: className, vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' }],
    imports: [], exports, data,
    textSection: { name: className, vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' },
    meta: { 'class': className, 'version': `${major}.${minor}`, 'java': major >= 45 ? `Java ${major - 44}` : '?' }
  }
}

// ────────────────────────────────────────────────────────────
// DEX (Android)
// ────────────────────────────────────────────────────────────
function parseDEX(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  let v = ''
  for (let i = 4; i < 8 && data[i] !== 0; i++) v += String.fromCharCode(data[i])
  const stringIdsSize = u32(d, 0x38, true)
  const stringIdsOff = u32(d, 0x3c, true)
  const exports: string[] = []
  for (let i = 0; i < Math.min(stringIdsSize, 1000); i++) {
    const sOff = u32(d, stringIdsOff + i * 4, true)
    let off = sOff
    let len = 0, shift = 0, b
    do { b = data[off++]; len |= (b & 0x7f) << shift; shift += 7 } while (b & 0x80)
    let s = ''
    for (let j = 0; j < Math.min(len, 200); j++) s += String.fromCharCode(data[off + j])
    if (s) exports.push(s)
  }
  return {
    format: 'DEX', arch: 'dalvik', bits: 32, entryPoint: 0,
    sections: [{ name: 'classes.dex', vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' }],
    imports: [], exports, data,
    textSection: { name: 'classes.dex', vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' },
    meta: { 'version': v.trim(), 'strings': stringIdsSize }
  }
}

// ────────────────────────────────────────────────────────────
// Python .pyc
// ────────────────────────────────────────────────────────────
function parsePYC(data: Uint8Array): ParsedBinary {
  const d = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const magic = u32(d, 0, true)
  const pyVersion: Record<number, string> = {
    0xa70d0d0a: 'Python 3.11', 0xa80d0d0a: 'Python 3.12',
    0x420d0d0a: 'Python 3.10', 0x550d0d0a: 'Python 3.9',
    0x610d0d0a: 'Python 3.8', 0x330d0d0a: 'Python 3.7',
  }
  return {
    format: 'Python/pyc', arch: 'python', bits: 32, entryPoint: 16,
    sections: [{ name: 'code', vaddr: 16, size: data.length - 16, fileOffset: 16, flags: 'X' }],
    imports: [], exports: [], data,
    textSection: { name: 'code', vaddr: 16, size: data.length - 16, fileOffset: 16, flags: 'X' },
    meta: { 'magic': '0x' + magic.toString(16), 'version': pyVersion[magic] || 'Unknown' }
  }
}

// ────────────────────────────────────────────────────────────
// Raw
// ────────────────────────────────────────────────────────────
function parseRaw(data: Uint8Array): ParsedBinary {
  return {
    format: 'Raw', arch: 'x64', bits: 64, entryPoint: 0,
    sections: [{ name: 'raw', vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' }],
    imports: [], exports: [], data,
    textSection: { name: 'raw', vaddr: 0, size: data.length, fileOffset: 0, flags: 'X' },
    meta: {}
  }
}

export function parseBinary(data: Uint8Array): ParsedBinary {
  const fmt = detectFormat(data)
  try {
    if (fmt === 'ELF') return parseELF(data)
    if (fmt === 'PE') return parsePE(data)
    if (fmt === 'Mach-O') return parseMachO(data)
    if (fmt === 'Mach-O/FAT') return parseFatMachO(data)
    if (fmt === 'WASM') return parseWASM(data)
    if (fmt === 'Java') return parseJava(data)
    if (fmt === 'DEX') return parseDEX(data)
    if (fmt === 'Python/pyc') return parsePYC(data)
    if (fmt === 'AR' || fmt === 'ZIP/JAR/APK') {
      const p = parseRaw(data)
      return { ...p, format: fmt, meta: { 'note': 'archive — extract to analyze contents' } }
    }
  } catch (e) {
    console.error('parse error', e)
  }
  return parseRaw(data)
}

export function extractStrings(data: Uint8Array, minLen = 5): { offset: number, value: string }[] {
  const out: { offset: number, value: string }[] = []
  let start = -1
  let current = ''
  for (let i = 0; i < data.length; i++) {
    const b = data[i]
    if (b >= 0x20 && b < 0x7f) {
      if (start === -1) start = i
      current += String.fromCharCode(b)
    } else {
      if (current.length >= minLen) out.push({ offset: start, value: current })
      start = -1
      current = ''
    }
    if (out.length >= 10000) break
  }
  if (current.length >= minLen) out.push({ offset: start, value: current })
  return out
}
