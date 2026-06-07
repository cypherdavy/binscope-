import type { Section } from '../binary/parse'

interface Props {
  sections: Section[]
  onPick: (s: Section) => void
  active?: Section
}

export function SectionsView({ sections, onPick, active }: Props) {
  return (
    <div className="overflow-auto font-mono text-xs">
      <table className="w-full">
        <thead className="sticky top-0 bg-zinc-950 text-zinc-500 text-left">
          <tr>
            <th className="py-2 px-3 font-medium">Name</th>
            <th className="py-2 px-3 font-medium">VAddr</th>
            <th className="py-2 px-3 font-medium">Size</th>
            <th className="py-2 px-3 font-medium">Flags</th>
          </tr>
        </thead>
        <tbody>
          {sections.map((s, i) => (
            <tr
              key={i}
              onClick={() => onPick(s)}
              className={`cursor-pointer ${active?.name === s.name ? 'bg-amber-500/15' : 'hover:bg-zinc-900/50'}`}
            >
              <td className="py-1.5 px-3 text-zinc-200">{s.name || '(unnamed)'}</td>
              <td className="py-1.5 px-3 text-amber-500/70">0x{s.vaddr.toString(16)}</td>
              <td className="py-1.5 px-3 text-zinc-400">{s.size.toLocaleString()}</td>
              <td className="py-1.5 px-3 text-violet-300">{s.flags}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
