import { useEffect, useMemo, useState } from 'react'
import { DropZone } from './components/DropZone'
import { HexView } from './components/HexView'
import { DisasmView } from './components/DisasmView'
import { StringsView } from './components/StringsView'
import { SectionsView } from './components/SectionsView'
import { AIExplain } from './components/AIExplain'
import { OverviewPanel } from './components/OverviewPanel'
import { EntropyChart } from './components/EntropyChart'
import { FunctionsPanel } from './components/FunctionsPanel'
import { ImportsPanel } from './components/ImportsPanel'
import { YaraPanel } from './components/YaraPanel'
import { parseBinary, extractStrings, type ParsedBinary, type Section } from './binary/parse'
import { disassemble, type Instruction } from './binary/disasm'
import { analyze, type FileAnalysis } from './binary/analyze'
import { detectFunctions, type DetectedFunction } from './binary/functions'
import { scan, type RuleHit } from './binary/yara'

type Tab = 'overview' | 'disasm' | 'hex' | 'strings' | 'functions' | 'imports' | 'yara' | 'entropy'

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [parsed, setParsed] = useState<ParsedBinary | null>(null)
  const [instructions, setInstructions] = useState<Instruction[]>([])
  const [tab, setTab] = useState<Tab>('overview')
  const [activeSection, setActiveSection] = useState<Section | undefined>()
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null)
  const [yaraHits, setYaraHits] = useState<RuleHit[]>([])
  const [functions, setFunctions] = useState<DetectedFunction[]>([])
  const [activeFn, setActiveFn] = useState<DetectedFunction | undefined>()

  const strings = useMemo(() => parsed ? extractStrings(parsed.data) : [], [parsed])

  useEffect(() => {
    if (!parsed) return
    setAnalysis(null)
    analyze(parsed).then(setAnalysis)
    setYaraHits(scan(parsed.data))
  }, [parsed])

  useEffect(() => {
    if (!parsed || !activeSection) return
    setBusy(true)
    const slice = parsed.data.subarray(
      activeSection.fileOffset,
      activeSection.fileOffset + Math.min(activeSection.size, 256 * 1024)
    )
    disassemble(slice, activeSection.vaddr, parsed.arch).then(ins => {
      setInstructions(ins)
      setSelectedIdx(null)
      setFunctions(detectFunctions(ins, parsed.arch))
      setBusy(false)
    })
  }, [parsed, activeSection])

  function loadFile(f: File, bytes: Uint8Array) {
    setFile(f)
    const p = parseBinary(bytes)
    setParsed(p)
    setActiveSection(p.textSection)
    setTab('overview')
    setActiveFn(undefined)
  }

  function reset() {
    setFile(null); setParsed(null); setInstructions([])
    setActiveSection(undefined); setSelectedIdx(null); setAnalysis(null)
    setYaraHits([]); setFunctions([]); setActiveFn(undefined)
  }

  function jumpToFunction(fn: DetectedFunction) {
    setActiveFn(fn)
    setSelectedIdx(fn.startIdx)
    setTab('disasm')
  }

  const selection = useMemo(() => {
    if (selectedIdx === null) return []
    const start = Math.max(0, selectedIdx - 5)
    const end = Math.min(instructions.length, selectedIdx + 20)
    return instructions.slice(start, end)
  }, [instructions, selectedIdx])

  const tabs: { id: Tab, label: string, count?: number }[] = [
    { id: 'overview', label: 'overview' },
    { id: 'disasm', label: 'disasm' },
    { id: 'functions', label: 'functions', count: functions.length },
    { id: 'hex', label: 'hex' },
    { id: 'strings', label: 'strings', count: strings.length },
    { id: 'imports', label: 'imports', count: parsed ? parsed.imports.length + parsed.exports.length : 0 },
    { id: 'yara', label: 'rules', count: yaraHits.length },
    { id: 'entropy', label: 'entropy' },
  ]

  const contentHeight = () => Math.max(300, window.innerHeight - 145)

  return (
    <div className={`${parsed ? 'h-screen' : 'min-h-screen'} flex flex-col text-zinc-200 relative`}>
      <div className="aurora"><div className="aurora-3" /></div>
      <div className="grid-bg" />
      <div className="noise" />

      <header className="relative z-10 flex items-center justify-between px-5 py-3 border-b border-white/5 glass">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 rounded-lg bg-amber-500/40 blur-md" />
            <div className="relative w-9 h-9 rounded-lg bg-gradient-to-br from-amber-400 to-fuchsia-500 flex items-center justify-center text-zinc-950 font-bold text-lg">
              ⌬
            </div>
          </div>
          <div>
            <div className="font-bold tracking-tight text-base" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
              BinScope
            </div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">
              reverse engineering · in your browser
            </div>
          </div>
        </div>
        {parsed && (
          <div className="flex items-center gap-2 text-xs">
            <Pill label={parsed.format} color="amber" />
            <Pill label={parsed.arch} color="sky" />
            <Pill label={`${parsed.bits}-bit`} color="violet" />
            {analysis && (
              <Pill label={`H ${analysis.entropy.toFixed(2)}`} color={analysis.entropy > 7.4 ? 'amber' : 'emerald'} />
            )}
            <button
              onClick={reset}
              className="ml-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-md text-zinc-200 transition"
            >
              ↻ new file
            </button>
          </div>
        )}
      </header>

      {!parsed ? (
        <DropZone onLoad={loadFile} />
      ) : (
        <div className="relative z-10 flex-1 grid grid-cols-[260px_1fr_360px] overflow-hidden gap-px bg-white/5">
          <aside className="overflow-hidden flex flex-col glass">
            <div className="p-3 border-b border-white/5 text-[10px] uppercase tracking-[0.2em] text-zinc-500 flex items-center gap-2">
              <span className="w-1 h-1 rounded-full bg-amber-400" />
              Sections
              <span className="ml-auto text-zinc-600 normal-case tracking-normal truncate max-w-[140px]">{file?.name}</span>
            </div>
            <SectionsView sections={parsed.sections} onPick={setActiveSection} active={activeSection} />
          </aside>

          <main className="flex flex-col overflow-hidden glass">
            <div className="flex items-center border-b border-white/5 overflow-x-auto">
              {tabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`relative whitespace-nowrap px-4 py-2.5 text-[11px] uppercase tracking-[0.18em] transition ${
                    tab === t.id ? 'text-amber-300' : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {t.label}{t.count !== undefined && t.count > 0 && (
                    <span className="ml-1.5 text-zinc-600 normal-case tracking-normal">· {t.count}</span>
                  )}
                  {tab === t.id && (
                    <span className="absolute left-2 right-2 bottom-0 h-[2px] bg-gradient-to-r from-amber-400 to-fuchsia-500 rounded-full" />
                  )}
                </button>
              ))}
              {busy && (
                <span className="ml-auto px-4 py-2 text-xs text-amber-300 flex items-center gap-2 whitespace-nowrap">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 glow-pulse" />
                  disassembling…
                </span>
              )}
            </div>
            <div className="flex-1 overflow-hidden">
              {tab === 'overview' && (
                <OverviewPanel parsed={parsed} analysis={analysis} fileName={file?.name || 'binary'} />
              )}
              {tab === 'disasm' && (
                <DisasmView
                  instructions={instructions}
                  height={contentHeight()}
                  selectedIdx={selectedIdx}
                  onSelect={setSelectedIdx}
                />
              )}
              {tab === 'functions' && (
                <FunctionsPanel
                  functions={functions}
                  height={contentHeight()}
                  onPick={jumpToFunction}
                  selected={activeFn}
                />
              )}
              {tab === 'hex' && (
                <HexView
                  data={activeSection
                    ? parsed.data.subarray(activeSection.fileOffset, activeSection.fileOffset + activeSection.size)
                    : parsed.data}
                  baseAddr={activeSection?.vaddr || 0}
                  height={contentHeight()}
                />
              )}
              {tab === 'strings' && (
                <StringsView strings={strings} height={contentHeight()} />
              )}
              {tab === 'imports' && (
                <ImportsPanel imports={parsed.imports} exports={parsed.exports} height={contentHeight()} />
              )}
              {tab === 'yara' && <YaraPanel hits={yaraHits} />}
              {tab === 'entropy' && <EntropyChart analysis={analysis} />}
            </div>
          </main>

          <aside className="overflow-hidden flex flex-col glass">
            <div className="p-3 border-b border-white/5 text-[10px] uppercase tracking-[0.2em] text-zinc-500 flex items-center gap-2">
              <span className="w-1 h-1 rounded-full bg-fuchsia-400 glow-pulse" />
              AI Analyst
              <span className="ml-auto px-1.5 py-0.5 rounded bg-fuchsia-500/15 text-fuchsia-300 normal-case tracking-normal text-[10px] font-mono">
                claude-opus-4.7
              </span>
            </div>
            <AIExplain selection={selection} arch={parsed.arch} format={parsed.format} />
          </aside>
        </div>
      )}

      <footer className="relative z-10 px-5 py-2 border-t border-white/5 text-[11px] text-zinc-500 flex justify-between glass">
        <span className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 glow-pulse" />
          your binary never leaves this tab
        </span>
        <span className="font-mono text-zinc-600">BinScope · v0.2</span>
      </footer>
    </div>
  )
}

function Pill({ label, color }: { label: string, color: string }) {
  const colors: Record<string, string> = {
    amber: 'bg-amber-500/15 text-amber-300 border-amber-400/30',
    sky: 'bg-sky-500/15 text-sky-300 border-sky-400/30',
    violet: 'bg-violet-500/15 text-violet-300 border-violet-400/30',
    emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30'
  }
  return (
    <span className={`pill-glow px-2.5 py-1 rounded-md border font-mono text-[11px] ${colors[color]}`}>
      {label}
    </span>
  )
}
