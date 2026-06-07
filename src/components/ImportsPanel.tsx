import { useMemo, useState } from 'react'
import { FixedSizeList } from 'react-window'
import type { ImportInfo } from '../binary/parse'

interface Props {
  imports: ImportInfo[]
  exports: string[]
  height: number
}

type Tab = 'imports' | 'exports'

export function ImportsPanel({ imports, exports, height }: Props) {
  const [tab, setTab] = useState<Tab>(imports.length ? 'imports' : 'exports')
  const [q, setQ] = useState('')

  const filteredImports = useMemo(() => {
    if (!q) return imports
    const ql = q.toLowerCase()
    return imports.filter(i => i.name.toLowerCase().includes(ql) || (i.library || '').toLowerCase().includes(ql))
  }, [imports, q])
  const filteredExports = useMemo(() => {
    if (!q) return exports
    const ql = q.toLowerCase()
    return exports.filter(e => e.toLowerCase().includes(ql))
  }, [exports, q])

  return (
    <div className="flex flex-col" style={{ height }}>
      <div className="flex border-b border-white/5">
        {(['imports', 'exports'] as Tab[]).map(t => (
          <button key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-[11px] uppercase tracking-wider ${tab === t ? 'text-amber-300 border-b-2 border-amber-400' : 'text-zinc-500 hover:text-zinc-300'}`}>
            {t} · {t === 'imports' ? imports.length : exports.length}
          </button>
        ))}
      </div>
      <div className="p-2 border-b border-white/5">
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="Search…"
          className="w-full bg-zinc-900/60 border border-white/10 rounded px-2 py-1 text-xs focus:outline-none focus:border-amber-500/50"
        />
      </div>
      <div className="flex-1 overflow-hidden">
        {tab === 'imports' ? (
          <FixedSizeList height={height - 90} itemCount={filteredImports.length} itemSize={22} width="100%" className="font-mono text-xs">
            {({ index, style }) => {
              const i = filteredImports[index]
              return (
                <div style={style} className="flex gap-3 px-3 hover:bg-white/5">
                  <span className="text-violet-300 w-32 truncate">{i.library || ''}</span>
                  <span className="text-zinc-200 flex-1 truncate">{i.name}</span>
                  {i.ordinal !== undefined && <span className="text-zinc-500">#{i.ordinal}</span>}
                </div>
              )
            }}
          </FixedSizeList>
        ) : (
          <FixedSizeList height={height - 90} itemCount={filteredExports.length} itemSize={22} width="100%" className="font-mono text-xs">
            {({ index, style }) => (
              <div style={style} className="px-3 hover:bg-white/5 text-zinc-200 truncate">
                {filteredExports[index]}
              </div>
            )}
          </FixedSizeList>
        )}
      </div>
    </div>
  )
}
