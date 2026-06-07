import type { FileAnalysis } from '../binary/analyze'

interface Props {
  analysis: FileAnalysis | null
}

export function EntropyChart({ analysis }: Props) {
  if (!analysis) return <div className="p-4 text-xs text-zinc-500">Loading…</div>
  const items = analysis.entropyPerSection.filter(s => s.size > 0).slice(0, 20)
  if (!items.length) return <div className="p-4 text-xs text-zinc-500">No section data.</div>
  return (
    <div className="p-4">
      <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 mb-3">
        Entropy per section · 0 (uniform) → 8 (random)
      </div>
      <div className="space-y-1.5">
        {items.map(s => {
          const pct = (s.entropy / 8) * 100
          const hot = s.entropy > 7.4
          return (
            <div key={s.name} className="flex items-center gap-3 text-xs font-mono">
              <span className="w-32 truncate text-zinc-300">{s.name}</span>
              <div className="flex-1 h-2.5 bg-white/5 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${hot ? 'bg-gradient-to-r from-amber-500 to-rose-500' : 'bg-gradient-to-r from-emerald-500 to-cyan-500'}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className={`w-12 text-right ${hot ? 'text-amber-300' : 'text-zinc-400'}`}>
                {s.entropy.toFixed(2)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
