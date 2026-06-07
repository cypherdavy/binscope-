import { useRef, useState, useEffect } from 'react'

interface Props {
  onLoad: (file: File, bytes: Uint8Array) => void
}

const SAMPLE_CODE = [
  '$ binscope analyze suspicious.exe',
  '> detected: PE / x86_64',
  '> sections: .text .rdata .data .pdata',
  '> entropy spike @ 0x401a00  (possible packer)',
  '> ai: "this looks like a custom xor decryptor…"',
  '> done. drop your binary above ↑',
]

export function DropZone({ onLoad }: Props) {
  const [drag, setDrag] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const [typed, setTyped] = useState('')
  const [lineIdx, setLineIdx] = useState(0)

  useEffect(() => {
    if (lineIdx >= SAMPLE_CODE.length) {
      const t = setTimeout(() => { setTyped(''); setLineIdx(0) }, 3500)
      return () => clearTimeout(t)
    }
    const target = SAMPLE_CODE.slice(0, lineIdx + 1).join('\n')
    if (typed.length < target.length) {
      const t = setTimeout(() => setTyped(target.slice(0, typed.length + 1)), 22)
      return () => clearTimeout(t)
    }
    const t = setTimeout(() => setLineIdx(lineIdx + 1), 600)
    return () => clearTimeout(t)
  }, [typed, lineIdx])

  async function handleFile(file: File) {
    const buf = await file.arrayBuffer()
    onLoad(file, new Uint8Array(buf))
  }

  return (
    <div className="relative flex-1 flex flex-col items-center justify-center px-6 py-10 overflow-hidden">
      <div className="scanline" />

      <div className="fade-up text-center mb-8 max-w-3xl">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass text-[11px] uppercase tracking-[0.2em] text-amber-300/80 mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 glow-pulse" />
          fully client-side · zero uploads
        </div>
        <h1 className="text-5xl sm:text-6xl font-extrabold tracking-tight leading-[1.05]">
          Reverse engineer <span className="shimmer">anything</span>.<br />
          Right in your browser.
        </h1>
        <p className="text-zinc-400 mt-5 text-lg max-w-xl mx-auto">
          Drop in a PE, ELF, or Mach-O binary. Get disassembly, hex, strings,
          and AI analysis — without installing a thing.
        </p>
      </div>

      <div
        onDragOver={e => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={e => {
          e.preventDefault(); setDrag(false)
          const f = e.dataTransfer.files?.[0]
          if (f) handleFile(f)
        }}
        onClick={() => inputRef.current?.click()}
        className={`fade-up relative group w-full max-w-2xl rounded-3xl cursor-pointer transition-all duration-300 ${
          drag ? 'scale-[1.02]' : 'hover:scale-[1.01]'
        }`}
        style={{ animationDelay: '0.1s' }}
      >
        <div className={`absolute -inset-0.5 rounded-3xl bg-gradient-to-r from-amber-500 via-fuchsia-500 to-cyan-500 opacity-60 blur-md transition-opacity ${drag ? 'opacity-100' : 'group-hover:opacity-80'}`} />
        <div className="relative glass rounded-3xl px-12 py-14 flex flex-col items-center text-center">
          <div className={`relative w-20 h-20 mb-5 flex items-center justify-center rounded-2xl bg-gradient-to-br from-amber-500/20 to-fuchsia-500/20 border border-amber-500/30 ${drag ? 'pulse-ring' : 'float'}`}>
            <span className="text-4xl">⌬</span>
            <span className="absolute inset-0 rounded-2xl border border-amber-400/40 spin-slow" />
          </div>
          <div className="text-2xl font-bold text-zinc-100">
            {drag ? 'Release to analyze' : 'Drop a binary here'}
          </div>
          <div className="text-sm text-zinc-400 mt-2">
            or <span className="text-amber-400 underline underline-offset-2">browse files</span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2 mt-6">
            {['PE', 'ELF', 'Mach-O', 'x86', 'x64', 'ARM', 'ARM64', 'MIPS'].map(t => (
              <span key={t} className="px-2.5 py-1 rounded-full text-[10px] font-mono uppercase tracking-wider bg-zinc-900/70 border border-zinc-700 text-zinc-400">
                {t}
              </span>
            ))}
          </div>
        </div>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
        />
      </div>

      <div className="fade-up mt-10 w-full max-w-2xl glass rounded-xl p-4 font-mono text-[12px] leading-relaxed text-emerald-300/90 border border-emerald-500/10"
           style={{ animationDelay: '0.25s' }}>
        <div className="flex items-center gap-1.5 mb-2">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
          <span className="ml-3 text-[10px] uppercase tracking-widest text-zinc-500">binscope &gt; terminal</span>
        </div>
        <pre className="whitespace-pre-wrap text-zinc-300">{typed}<span className="caret text-amber-400">▌</span></pre>
      </div>

      <div className="fade-up flex items-center gap-6 mt-8 text-[11px] text-zinc-500"
           style={{ animationDelay: '0.4s' }}>
        <Stat icon="⚡" label="disasm <2s" />
        <Stat icon="🛡" label="never uploaded" />
        <Stat icon="✨" label="AI-assisted" />
      </div>
    </div>
  )
}

function Stat({ icon, label }: { icon: string, label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span>{icon}</span>
      <span>{label}</span>
    </span>
  )
}
