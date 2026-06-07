import { useState, useMemo } from 'react'
import { FixedSizeList } from 'react-window'

interface Props {
  strings: { offset: number, value: string }[]
  height: number
}

export function StringsView({ strings, height }: Props) {
  const [q, setQ] = useState('')
  const filtered = useMemo(() => {
    if (!q) return strings
    const ql = q.toLowerCase()
    return strings.filter(s => s.value.toLowerCase().includes(ql))
  }, [strings, q])

  return (
    <div className="flex flex-col" style={{ height }}>
      <div className="p-2 border-b border-zinc-800">
        <input
          type="text"
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder={`Search ${strings.length} strings…`}
          className="w-full bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-amber-500/50"
        />
      </div>
      <FixedSizeList
        height={height - 44}
        itemCount={filtered.length}
        itemSize={22}
        width="100%"
        className="font-mono text-xs"
      >
        {({ index, style }) => {
          const s = filtered[index]
          return (
            <div style={style} className="flex gap-3 px-3 hover:bg-zinc-900/50">
              <span className="text-amber-500/70 w-20 shrink-0">
                {s.offset.toString(16).padStart(8, '0')}
              </span>
              <span className="text-emerald-300/90 truncate">{s.value}</span>
            </div>
          )
        }}
      </FixedSizeList>
    </div>
  )
}
