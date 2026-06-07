import { FixedSizeList } from 'react-window'
import { useState, useMemo } from 'react'
import type { DetectedFunction } from '../binary/functions'

interface Props {
  functions: DetectedFunction[]
  height: number
  onPick: (fn: DetectedFunction) => void
  selected?: DetectedFunction
}

export function FunctionsPanel({ functions, height, onPick, selected }: Props) {
  const [q, setQ] = useState('')
  const filtered = useMemo(() => {
    if (!q) return functions
    return functions.filter(f => f.name.toLowerCase().includes(q.toLowerCase()))
  }, [functions, q])

  return (
    <div className="flex flex-col" style={{ height }}>
      <div className="p-2 border-b border-white/5">
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder={`Search ${functions.length} functions…`}
          className="w-full bg-zinc-900/60 border border-white/10 rounded px-2 py-1 text-xs focus:outline-none focus:border-amber-500/50"
        />
      </div>
      {filtered.length === 0 ? (
        <div className="p-6 text-xs text-zinc-500">No functions detected. Try a different section.</div>
      ) : (
        <FixedSizeList
          height={height - 44}
          itemCount={filtered.length}
          itemSize={26}
          width="100%"
          className="font-mono text-xs"
        >
          {({ index, style }) => {
            const fn = filtered[index]
            const isSel = selected?.address === fn.address
            return (
              <div
                style={style}
                onClick={() => onPick(fn)}
                className={`flex gap-3 px-3 cursor-pointer items-center ${isSel ? 'bg-amber-500/15' : 'hover:bg-white/5'}`}
              >
                <span className="text-amber-500/70 w-20">{fn.address.toString(16).padStart(8, '0')}</span>
                <span className="text-zinc-200 flex-1 truncate">{fn.name}</span>
                <span className="text-zinc-500 text-[10px]">{fn.size}B</span>
                {fn.refs > 0 && (
                  <span className="text-sky-300 text-[10px] px-1.5 py-0.5 rounded bg-sky-500/15">×{fn.refs}</span>
                )}
              </div>
            )
          }}
        </FixedSizeList>
      )}
    </div>
  )
}
