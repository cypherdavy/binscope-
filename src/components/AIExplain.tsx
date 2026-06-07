import { useState } from 'react'
import type { Instruction } from '../binary/disasm'

interface Props {
  selection: Instruction[]
  arch: string
  format: string
}

export function AIExplain({ selection, arch, format }: Props) {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('anthropic_key') || '')
  const [out, setOut] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  async function explain() {
    if (!apiKey) { setErr('Set your Anthropic API key first.'); return }
    if (!selection.length) { setErr('Select instructions in the disassembly.'); return }
    setErr(''); setLoading(true); setOut('')
    localStorage.setItem('anthropic_key', apiKey)

    const asm = selection.map(i =>
      `${i.address.toString(16).padStart(8, '0')}  ${i.mnemonic.padEnd(8)} ${i.opStr}`
    ).join('\n')

    const prompt = `You are a senior reverse engineer. Analyze this ${arch} assembly from a ${format} binary.
Explain in plain English:
1. What this code does (high level).
2. Suggested function purpose / algorithm if recognizable (crypto, hashing, packing, string ops, etc.).
3. Suggested variable / register names.
4. Any anti-analysis or suspicious patterns.

\`\`\`asm
${asm}
\`\`\``

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model: 'claude-opus-4-7',
          max_tokens: 1024,
          messages: [{ role: 'user', content: prompt }]
        })
      })
      if (!res.ok) {
        const t = await res.text()
        throw new Error(`${res.status}: ${t.slice(0, 200)}`)
      }
      const data = await res.json()
      const text = data.content?.[0]?.text ?? '(no response)'
      setOut(text)
    } catch (e: any) {
      setErr(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-zinc-800 space-y-2">
        <div className="flex items-center gap-2">
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="sk-ant-…  (stored locally only)"
            className="flex-1 bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs focus:outline-none focus:border-amber-500/50"
          />
          <button
            onClick={explain}
            disabled={loading}
            className="px-3 py-1 bg-amber-500 hover:bg-amber-400 disabled:opacity-40 text-zinc-950 rounded text-xs font-semibold"
          >
            {loading ? '…' : 'Explain'}
          </button>
        </div>
        <div className="text-[11px] text-zinc-500">
          {selection.length} instruction{selection.length === 1 ? '' : 's'} selected
        </div>
      </div>
      <div className="flex-1 overflow-auto p-3 text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed">
        {err && <div className="text-rose-400 text-xs mb-2">{err}</div>}
        {out || <span className="text-zinc-600">AI analysis will appear here. Select instructions and click Explain.</span>}
      </div>
    </div>
  )
}
