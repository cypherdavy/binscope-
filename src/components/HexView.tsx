import { FixedSizeList } from 'react-window'
import { useMemo } from 'react'

interface Props {
  data: Uint8Array
  baseAddr?: number
  height: number
}

const ROW_BYTES = 16

export function HexView({ data, baseAddr = 0, height }: Props) {
  const rows = useMemo(() => Math.ceil(data.length / ROW_BYTES), [data])

  return (
    <FixedSizeList
      height={height}
      itemCount={rows}
      itemSize={22}
      width="100%"
      className="font-mono text-xs"
    >
      {({ index, style }) => {
        const off = index * ROW_BYTES
        const slice = data.subarray(off, off + ROW_BYTES)
        const hex: string[] = []
        const ascii: string[] = []
        for (let i = 0; i < ROW_BYTES; i++) {
          if (i < slice.length) {
            hex.push(slice[i].toString(16).padStart(2, '0'))
            const c = slice[i]
            ascii.push(c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.')
          } else {
            hex.push('  ')
            ascii.push(' ')
          }
        }
        return (
          <div style={style} className="flex gap-4 px-4 hover:bg-zinc-900/50">
            <span className="text-amber-500/70 w-20">
              {(baseAddr + off).toString(16).padStart(8, '0')}
            </span>
            <span className="text-zinc-300 tracking-wider">
              {hex.slice(0, 8).join(' ')}  {hex.slice(8).join(' ')}
            </span>
            <span className="text-emerald-400/80">{ascii.join('')}</span>
          </div>
        )
      }}
    </FixedSizeList>
  )
}
