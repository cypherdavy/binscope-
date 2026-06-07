import { FixedSizeList } from 'react-window'
import type { Instruction } from '../binary/disasm'

interface Props {
  instructions: Instruction[]
  height: number
  selectedIdx: number | null
  onSelect: (idx: number) => void
}

function colorFor(mnemonic: string): string {
  if (mnemonic.startsWith('j') || mnemonic === 'call') return 'text-amber-400'
  if (mnemonic === 'ret') return 'text-rose-400'
  if (mnemonic === 'mov' || mnemonic === 'lea') return 'text-sky-300'
  if (mnemonic === 'push' || mnemonic === 'pop') return 'text-violet-300'
  if (mnemonic === 'nop' || mnemonic === 'int3') return 'text-zinc-500'
  return 'text-emerald-300'
}

export function DisasmView({ instructions, height, selectedIdx, onSelect }: Props) {
  if (!instructions.length) {
    return (
      <div className="flex items-center justify-center text-zinc-500 text-sm" style={{ height }}>
        No instructions decoded yet.
      </div>
    )
  }
  return (
    <FixedSizeList
      height={height}
      itemCount={instructions.length}
      itemSize={22}
      width="100%"
      className="font-mono text-xs"
    >
      {({ index, style }) => {
        const ins = instructions[index]
        const selected = index === selectedIdx
        const bytesStr = Array.from(ins.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
        return (
          <div
            style={style}
            onClick={() => onSelect(index)}
            className={`flex gap-4 px-4 cursor-pointer ${selected ? 'bg-amber-500/15' : 'hover:bg-zinc-900/50'}`}
          >
            <span className="text-amber-500/70 w-24">
              {ins.address.toString(16).padStart(8, '0')}
            </span>
            <span className="text-zinc-500 w-40 truncate">{bytesStr}</span>
            <span className={`w-16 font-semibold ${colorFor(ins.mnemonic)}`}>{ins.mnemonic}</span>
            <span className="text-zinc-200 flex-1 truncate">{ins.opStr}</span>
          </div>
        )
      }}
    </FixedSizeList>
  )
}
