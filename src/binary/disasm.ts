import type { Arch } from './parse'

export interface Instruction {
  address: number
  bytes: Uint8Array
  mnemonic: string
  opStr: string
  size: number
}

let capstoneReady: Promise<any> | null = null

async function loadCapstone() {
  if (!capstoneReady) {
    capstoneReady = import('capstone-wasm').then(async (mod: any) => {
      if (mod.loadCapstone) await mod.loadCapstone()
      else if (mod.Capstone?.load) await mod.Capstone.load()
      else if (mod.default?.load) await mod.default.load()
      return mod
    })
  }
  return capstoneReady
}

function archToCs(mod: any, arch: Arch): { archConst: number, modeConst: number } {
  const C = mod.Const || mod.default?.Const || mod
  switch (arch) {
    case 'x86': return { archConst: C.ARCH_X86 ?? 3, modeConst: C.MODE_32 ?? 4 }
    case 'x64': return { archConst: C.ARCH_X86 ?? 3, modeConst: C.MODE_64 ?? 8 }
    case 'arm': return { archConst: C.ARCH_ARM ?? 1, modeConst: C.MODE_ARM ?? 0 }
    case 'arm64': return { archConst: C.ARCH_ARM64 ?? 2, modeConst: C.MODE_ARM ?? 0 }
    case 'mips': return { archConst: C.ARCH_MIPS ?? 4, modeConst: C.MODE_32 ?? 4 }
    default: return { archConst: 3, modeConst: 8 }
  }
}

export async function disassemble(
  bytes: Uint8Array,
  baseAddr: number,
  arch: Arch,
  maxBytes = 65536
): Promise<Instruction[]> {
  const slice = bytes.length > maxBytes ? bytes.slice(0, maxBytes) : bytes
  try {
    const mod = await loadCapstone()
    const { archConst, modeConst } = archToCs(mod, arch)
    const Capstone = mod.Capstone || mod.default?.Capstone || mod.default
    const cs = new Capstone(archConst, modeConst)
    const raw = cs.disasm(slice, baseAddr)
    const result: Instruction[] = (raw || []).map((i: any) => ({
      address: Number(i.address),
      bytes: i.bytes instanceof Uint8Array ? i.bytes : new Uint8Array(i.bytes || []),
      mnemonic: i.mnemonic,
      opStr: i.opStr ?? i.op_str ?? '',
      size: i.size
    }))
    cs.close?.()
    return result
  } catch (e) {
    console.warn('capstone-wasm unavailable, using fallback', e)
    return fallbackDisasm(slice, baseAddr)
  }
}

function fallbackDisasm(bytes: Uint8Array, baseAddr: number): Instruction[] {
  const out: Instruction[] = []
  let addr = baseAddr
  let i = 0
  while (i < bytes.length && out.length < 4000) {
    const b = bytes[i]
    const inst = decodeOne(bytes, i)
    out.push({
      address: addr,
      bytes: bytes.slice(i, i + inst.size),
      mnemonic: inst.mnemonic,
      opStr: inst.opStr,
      size: inst.size
    })
    addr += inst.size
    i += inst.size
  }
  return out
}

function decodeOne(b: Uint8Array, i: number): { mnemonic: string, opStr: string, size: number } {
  const op = b[i]
  if (op === 0x90) return { mnemonic: 'nop', opStr: '', size: 1 }
  if (op === 0xc3) return { mnemonic: 'ret', opStr: '', size: 1 }
  if (op === 0xcc) return { mnemonic: 'int3', opStr: '', size: 1 }
  if (op >= 0x50 && op <= 0x57) return { mnemonic: 'push', opStr: regName(op - 0x50), size: 1 }
  if (op >= 0x58 && op <= 0x5f) return { mnemonic: 'pop', opStr: regName(op - 0x58), size: 1 }
  if (op === 0xe8) {
    const rel = readI32(b, i + 1)
    return { mnemonic: 'call', opStr: `0x${(rel >>> 0).toString(16)}`, size: 5 }
  }
  if (op === 0xe9) {
    const rel = readI32(b, i + 1)
    return { mnemonic: 'jmp', opStr: `0x${(rel >>> 0).toString(16)}`, size: 5 }
  }
  if (op === 0xeb) {
    return { mnemonic: 'jmp', opStr: `0x${(b[i + 1] || 0).toString(16)}`, size: 2 }
  }
  if (op === 0x48 || op === 0x49 || op === 0x4c || op === 0x4d) {
    const next = b[i + 1]
    if (next === 0x89) return { mnemonic: 'mov', opStr: decodeModRM(b, i + 2), size: 3 }
    if (next === 0x8b) return { mnemonic: 'mov', opStr: decodeModRM(b, i + 2), size: 3 }
    if (next === 0x83) return { mnemonic: 'add/sub', opStr: 'reg, imm8', size: 4 }
    return { mnemonic: 'rex', opStr: `0x${next.toString(16)}`, size: 2 }
  }
  if (op === 0xb8) {
    return { mnemonic: 'mov', opStr: `eax, 0x${readU32(b, i + 1).toString(16)}`, size: 5 }
  }
  return { mnemonic: 'db', opStr: `0x${op.toString(16).padStart(2, '0')}`, size: 1 }
}

function regName(n: number): string {
  return ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'][n] || `r${n}`
}
function readI32(b: Uint8Array, o: number): number {
  if (o + 3 >= b.length) return 0
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24))
}
function readU32(b: Uint8Array, o: number): number {
  return readI32(b, o) >>> 0
}
function decodeModRM(_b: Uint8Array, _o: number): string {
  return 'reg, reg'
}
