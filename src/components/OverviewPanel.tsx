import type { FileAnalysis } from '../binary/analyze'
import type { ParsedBinary } from '../binary/parse'

interface Props {
  parsed: ParsedBinary
  analysis: FileAnalysis | null
  fileName: string
}

export function OverviewPanel({ parsed, analysis, fileName }: Props) {
  if (!analysis) {
    return <div className="p-6 text-zinc-500 text-sm">Computing hashes & entropy…</div>
  }
  return (
    <div className="p-6 overflow-auto space-y-6">
      <div>
        <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 mb-2">File</div>
        <div className="font-mono text-lg text-zinc-100 truncate">{fileName}</div>
        <div className="text-xs text-zinc-500 mt-1">
          {analysis.size.toLocaleString()} bytes · {parsed.format} · {parsed.arch} · {parsed.bits}-bit
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <Card label="Entropy" value={analysis.entropy.toFixed(3)} hint="/ 8.0" tone={analysis.entropy > 7.4 ? 'warn' : 'ok'} />
        <Card label="Sections" value={parsed.sections.length.toString()} />
        <Card label="Imports" value={parsed.imports.length.toString()} />
        <Card label="Exports" value={parsed.exports.length.toString()} />
      </div>

      {analysis.isLikelyEncrypted && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
          ⚠ High entropy detected — file may be packed, encrypted, or compressed.
        </div>
      )}

      {analysis.packerHints.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 mb-2">Packer hints</div>
          <div className="flex gap-2 flex-wrap">
            {analysis.packerHints.map(p => (
              <span key={p} className="px-2 py-1 rounded-md bg-rose-500/15 text-rose-300 border border-rose-500/30 text-xs font-mono">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 mb-2">Hashes</div>
        <div className="space-y-2 font-mono text-[11px]">
          <HashRow label="MD5" value={analysis.md5} />
          <HashRow label="SHA1" value={analysis.sha1} />
          <HashRow label="SHA256" value={analysis.sha256} />
        </div>
      </div>

      {Object.keys(parsed.meta).length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500 mb-2">Metadata</div>
          <table className="w-full text-xs font-mono">
            <tbody>
              {Object.entries(parsed.meta).map(([k, v]) => (
                <tr key={k} className="border-b border-white/5">
                  <td className="py-1.5 text-zinc-500 pr-4">{k}</td>
                  <td className="py-1.5 text-zinc-200">{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Card({ label, value, hint, tone }: { label: string, value: string, hint?: string, tone?: 'warn' | 'ok' }) {
  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.03] p-3">
      <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">{label}</div>
      <div className={`mt-1 font-mono text-xl ${tone === 'warn' ? 'text-amber-300' : 'text-zinc-100'}`}>
        {value}<span className="text-zinc-600 text-xs ml-1">{hint}</span>
      </div>
    </div>
  )
}

function HashRow({ label, value }: { label: string, value: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-zinc-500 w-14 shrink-0">{label}</span>
      <span
        className="text-zinc-200 break-all cursor-pointer hover:text-amber-300"
        onClick={() => navigator.clipboard.writeText(value)}
        title="click to copy"
      >
        {value}
      </span>
    </div>
  )
}
