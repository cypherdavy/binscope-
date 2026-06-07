import type { Arch } from './parse'
import type { Instruction } from './disasm'

export interface DetectedFunction {
  address: number
  endAddress: number
  startIdx: number
  endIdx: number
  size: number
  name: string
  refs: number
}

export function detectFunctions(instructions: Instruction[], arch: Arch): DetectedFunction[] {
  if (!instructions.length) return []
  const starts = new Set<number>()
  starts.add(0)

  // x86/x64 prologue: push rbp; mov rbp, rsp  OR  sub rsp, N
  // arm64 prologue: stp x29, x30, [sp, ...]
  for (let i = 0; i < instructions.length - 1; i++) {
    const a = instructions[i]
    const b = instructions[i + 1]
    if (arch === 'x86' || arch === 'x64') {
      if (a.mnemonic === 'push' && /rbp|ebp/i.test(a.opStr) &&
          b.mnemonic === 'mov' && /rbp|ebp/i.test(b.opStr) && /rsp|esp/i.test(b.opStr)) {
        starts.add(i)
      }
      // also after a ret + alignment, next non-int3 is likely a function
      if (a.mnemonic === 'ret') {
        let j = i + 1
        while (j < instructions.length && (instructions[j].mnemonic === 'int3' || instructions[j].mnemonic === 'nop')) j++
        if (j < instructions.length) starts.add(j)
      }
    }
    if (arch === 'arm64') {
      if (a.mnemonic.startsWith('stp') && /x29/.test(a.opStr) && /x30/.test(a.opStr)) starts.add(i)
    }
    if (arch === 'arm') {
      if (a.mnemonic === 'push' && /lr/i.test(a.opStr)) starts.add(i)
    }
  }

  // call targets indicate function starts (best-effort, only direct calls with hex address)
  const refMap = new Map<number, number>()
  for (const ins of instructions) {
    if (ins.mnemonic === 'call' || ins.mnemonic === 'bl' || ins.mnemonic === 'blr') {
      const m = ins.opStr.match(/0x([0-9a-fA-F]+)/)
      if (m) {
        const target = parseInt(m[1], 16)
        refMap.set(target, (refMap.get(target) || 0) + 1)
      }
    }
  }
  const addrToIdx = new Map<number, number>()
  instructions.forEach((ins, idx) => addrToIdx.set(ins.address, idx))
  for (const [addr] of refMap) {
    const idx = addrToIdx.get(addr)
    if (idx !== undefined) starts.add(idx)
  }

  const sorted = [...starts].sort((a, b) => a - b)
  const fns: DetectedFunction[] = []
  for (let i = 0; i < sorted.length; i++) {
    const startIdx = sorted[i]
    const endIdx = (sorted[i + 1] ?? instructions.length) - 1
    if (endIdx < startIdx) continue
    const startAddr = instructions[startIdx].address
    const lastIns = instructions[endIdx]
    const endAddr = lastIns.address + lastIns.size
    fns.push({
      address: startAddr,
      endAddress: endAddr,
      startIdx, endIdx,
      size: endAddr - startAddr,
      name: `sub_${startAddr.toString(16)}`,
      refs: refMap.get(startAddr) || 0
    })
  }
  return fns
}
