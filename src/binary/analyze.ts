import type { ParsedBinary, Section } from './parse'

export interface FileAnalysis {
  size: number
  md5: string
  sha1: string
  sha256: string
  entropy: number
  entropyPerSection: { name: string, entropy: number, size: number }[]
  packerHints: string[]
  isLikelyEncrypted: boolean
}

function bytesToHex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0')
  return s
}

export async function hashAll(data: Uint8Array): Promise<{ md5: string, sha1: string, sha256: string }> {
  const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer
  const [sha1, sha256] = await Promise.all([
    crypto.subtle.digest('SHA-1', buf),
    crypto.subtle.digest('SHA-256', buf)
  ])
  return {
    md5: md5Hex(data),
    sha1: bytesToHex(sha1),
    sha256: bytesToHex(sha256)
  }
}

// Shannon entropy of a byte range, 0..8
export function entropy(data: Uint8Array, start = 0, length = data.length): number {
  const end = Math.min(start + length, data.length)
  const counts = new Uint32Array(256)
  let total = 0
  for (let i = start; i < end; i++) { counts[data[i]]++; total++ }
  if (!total) return 0
  let h = 0
  for (let i = 0; i < 256; i++) {
    if (counts[i]) {
      const p = counts[i] / total
      h -= p * Math.log2(p)
    }
  }
  return h
}

const KNOWN_PACKER_STRINGS: { needle: string, label: string }[] = [
  { needle: 'UPX!', label: 'UPX' },
  { needle: '.UPX0', label: 'UPX' },
  { needle: 'ASPack', label: 'ASPack' },
  { needle: 'PECompact', label: 'PECompact' },
  { needle: '.themida', label: 'Themida' },
  { needle: '.vmp0', label: 'VMProtect' },
  { needle: '.enigma', label: 'Enigma' },
  { needle: 'MEW', label: 'MEW' },
  { needle: 'FSG!', label: 'FSG' },
  { needle: 'PEtite', label: 'PEtite' },
  { needle: '.petite', label: 'PEtite' },
  { needle: 'NSPack', label: 'NSPack' },
  { needle: 'kkrunchy', label: 'kkrunchy' },
  { needle: '.mpress', label: 'MPRESS' },
]

export function findPackerHints(data: Uint8Array, sections: Section[]): string[] {
  const hints = new Set<string>()
  // section names
  for (const s of sections) {
    for (const p of KNOWN_PACKER_STRINGS) {
      if (s.name.toLowerCase().includes(p.needle.toLowerCase())) hints.add(p.label)
    }
    if (s.name === '.upx0' || s.name === '.upx1' || s.name === '.upx2') hints.add('UPX')
  }
  // raw bytes scan (small)
  const head = Math.min(data.length, 0x4000)
  const headStr = new TextDecoder('latin1').decode(data.subarray(0, head))
  for (const p of KNOWN_PACKER_STRINGS) {
    if (headStr.includes(p.needle)) hints.add(p.label)
  }
  return [...hints]
}

export async function analyze(parsed: ParsedBinary): Promise<FileAnalysis> {
  const hashes = await hashAll(parsed.data)
  const overall = entropy(parsed.data)
  const perSection = parsed.sections.slice(0, 32).map(s => ({
    name: s.name || '(unnamed)',
    entropy: entropy(parsed.data, s.fileOffset, s.size),
    size: s.size
  }))
  const packerHints = findPackerHints(parsed.data, parsed.sections)
  const isLikelyEncrypted = overall > 7.4 || perSection.some(p => p.entropy > 7.5 && p.size > 1024)
  return {
    size: parsed.data.length,
    md5: hashes.md5, sha1: hashes.sha1, sha256: hashes.sha256,
    entropy: overall, entropyPerSection: perSection,
    packerHints, isLikelyEncrypted
  }
}

// ===== MD5 (compact RFC 1321 implementation) =====
function md5Hex(input: Uint8Array): string {
  const out = md5(input)
  let s = ''
  for (let i = 0; i < 16; i++) s += out[i].toString(16).padStart(2, '0')
  return s
}

function md5(msg: Uint8Array): Uint8Array {
  const origLen = msg.length
  const bitLen = origLen * 8
  const pad = (origLen % 64 < 56) ? (56 - origLen % 64) : (120 - origLen % 64)
  const buf = new Uint8Array(origLen + pad + 8)
  buf.set(msg)
  buf[origLen] = 0x80
  const dv = new DataView(buf.buffer)
  dv.setUint32(buf.length - 8, bitLen >>> 0, true)
  dv.setUint32(buf.length - 4, Math.floor(bitLen / 0x100000000) >>> 0, true)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  const K = new Int32Array([
    -680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, -1473231341, -45705983,
    1770035416, -1958414417, -42063, -1990404162, 1804603682, -40341101, -1502002290, 1236535329,
    -165796510, -1069501632, 643717713, -373897302, -701558691, 38016083, -660478335, -405537848,
    568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 1735328473, -1926607734,
    -378558, -2022574463, 1839030562, -35309556, -1530992060, 1272893353, -155497632, -1094730640,
    681279174, -358537222, -722521979, 76029189, -640364487, -421815835, 530742520, -995338651,
    -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, -1051523, -2054922799,
    1873313359, -30611744, -1560198380, 1309151649, -145523070, -1120210379, 718787259, -343485551
  ])
  const S = new Int32Array([
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
  ])

  for (let off = 0; off < buf.length; off += 64) {
    const M = new Int32Array(16)
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F = 0, g = 0
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * i) % 16 }
      const tmp = D
      D = C; C = B
      const sum = (A + F + K[i] + M[g]) | 0
      B = (B + ((sum << S[i]) | (sum >>> (32 - S[i])))) | 0
      A = tmp
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0
  }
  const out = new Uint8Array(16)
  const odv = new DataView(out.buffer)
  odv.setInt32(0, a0, true); odv.setInt32(4, b0, true)
  odv.setInt32(8, c0, true); odv.setInt32(12, d0, true)
  return out
}
