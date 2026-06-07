# BinScope

**Reverse engineering, in your browser.** Drop any binary — PE, ELF, Mach-O, WASM, Java `.class`, Android DEX, Python `.pyc`, FAT Mach-O — and get a full triage: hashes, entropy, packer detection, disassembly, functions, imports/exports, YARA-style rule hits, strings, hex, and AI-powered analysis from Claude. Everything runs **client-side**. Your binary never leaves the tab.

![screenshot](docs/screenshot.png)

## Features

- **Multi-format parser:** PE / PE+ / .NET, ELF, Mach-O (single + FAT/Universal), WASM, Java class, Android DEX, Python pyc, ZIP/JAR/APK, AR archives, raw fallback
- **Multi-arch disassembly:** x86, x86_64, ARM, ARM64, MIPS, RISC-V (via Capstone-WASM)
- **Function detection** by prologue scanning + call-target inference
- **Imports / Exports** table for PE (IAT), ELF (`.dynsym`), Mach-O (LC_LOAD_DYLIB), WASM
- **Hashes** — MD5, SHA-1, SHA-256, all client-side
- **Entropy analysis** — Shannon entropy per section + visual chart; flags packed/encrypted blobs
- **Packer detection** — UPX, VMProtect, Themida, ASPack, PECompact, MPRESS, Enigma, MEW, FSG, PEtite, NSPack, kkrunchy
- **YARA-lite scanner** — built-in rules for crypto constants (AES, SHA-256, MD5, CRC32, RSA OID), suspicious APIs (anti-debug, process injection, network, persistence), known malware markers, compiler fingerprints
- **AI Analyst** — select instructions, click Explain, Claude tells you what the code does
- **Strings, hex, sections** views — virtualized for speed
- **Privacy by design** — no uploads, no server analysis. Your binary stays in the browser

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:5173.

## Deploy to GitHub Pages

1. Push this repo to GitHub as `binscope` (or change the `base` path in `vite.config.ts`).
2. In repo Settings → Pages → **Source: GitHub Actions**.
3. Push to `main`. The workflow at `.github/workflows/deploy.yml` builds with `GITHUB_PAGES=true` and publishes `dist/`.
4. Visit `https://<your-username>.github.io/binscope/`.

If you want a custom subdirectory (e.g. `/re/`), edit the `base` in `vite.config.ts`.

## How to use

1. Drop a binary anywhere on the landing page.
2. **Overview** shows hashes, entropy, packer hints, and metadata.
3. **Sections** panel (left) lets you switch which segment to disassemble.
4. **Disasm** is the main view — click an instruction to select it.
5. **Functions** lists detected subroutines; click to jump.
6. **Imports / Exports** lists DLL / shared-library symbols.
7. **Rules** shows YARA-style pattern hits, grouped by category.
8. **Entropy** chart flags encrypted/packed regions.
9. In the right panel, paste your Anthropic API key (stored in `localStorage` only) and click **Explain** — Claude analyzes the selected assembly.

## Roadmap

- Ghidra decompiler in WASM (C-like output)
- Shareable permalinks (gzip+base64 in URL for tiny binaries, OPFS for larger)
- Custom YARA rule editor
- Dynamic analysis sandbox (Unicorn-WASM)
- Multiplayer cursors for CTF teams
- Diff view between two binaries

## License

MIT. Capstone is BSD-3-Clause.
