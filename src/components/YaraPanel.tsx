import type { RuleHit } from '../binary/yara'

interface Props {
  hits: RuleHit[]
}

const catColors: Record<string, string> = {
  crypto: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  packer: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  suspicious: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  malware: 'bg-rose-600/20 text-rose-200 border-rose-500/40',
  compiler: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  string: 'bg-zinc-500/15 text-zinc-300 border-zinc-500/30',
}
const sevColors: Record<string, string> = {
  high: 'text-rose-400',
  med: 'text-amber-300',
  low: 'text-zinc-400'
}

export function YaraPanel({ hits }: Props) {
  if (!hits.length) {
    return (
      <div className="p-6 text-sm text-zinc-500">
        <span className="text-emerald-400">✓</span> No rule matches. Clean baseline (or unknown packer).
      </div>
    )
  }
  const grouped: Record<string, RuleHit[]> = {}
  for (const h of hits) {
    grouped[h.rule.category] = grouped[h.rule.category] || []
    grouped[h.rule.category].push(h)
  }
  return (
    <div className="overflow-auto p-4 space-y-5">
      <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">
        {hits.length} rule match{hits.length === 1 ? '' : 'es'} across {Object.keys(grouped).length} categor{Object.keys(grouped).length === 1 ? 'y' : 'ies'}
      </div>
      {Object.entries(grouped).map(([cat, items]) => (
        <div key={cat}>
          <div className="flex items-center gap-2 mb-2">
            <span className={`px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider ${catColors[cat]}`}>
              {cat}
            </span>
            <span className="text-xs text-zinc-500">{items.length}</span>
          </div>
          <div className="space-y-2">
            {items.map(h => (
              <div key={h.rule.id} className="rounded-lg border border-white/5 bg-white/[0.02] p-3">
                <div className="flex items-baseline justify-between gap-3">
                  <div className="font-semibold text-zinc-100 text-sm">{h.rule.name}</div>
                  <span className={`text-[10px] uppercase tracking-wider ${sevColors[h.rule.severity]}`}>
                    {h.rule.severity}
                  </span>
                </div>
                <div className="text-xs text-zinc-400 mt-1">{h.rule.description}</div>
                <div className="mt-2 text-[11px] font-mono text-zinc-500">
                  offsets: {h.offsets.slice(0, 6).map(o => '0x' + o.toString(16)).join(', ')}
                  {h.offsets.length > 6 && ` +${h.offsets.length - 6} more`}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
