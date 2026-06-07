export interface Rule {
  id: string
  name: string
  category: 'crypto' | 'packer' | 'suspicious' | 'malware' | 'compiler' | 'string'
  severity: 'low' | 'med' | 'high'
  patterns: (string | number[])[] // string for ascii, number[] for raw bytes
  description: string
}

export interface RuleHit {
  rule: Rule
  offsets: number[]
}

// A starter library — easy to extend.
export const RULES: Rule[] = [
  // === Crypto constants ===
  { id: 'aes_sbox', name: 'AES S-Box', category: 'crypto', severity: 'med',
    description: 'AES forward S-Box constants found.',
    patterns: [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]] },
  { id: 'aes_te0', name: 'AES Te0 table', category: 'crypto', severity: 'med',
    description: 'AES Te0 lookup table prefix.',
    patterns: [[0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8]] },
  { id: 'sha256_init', name: 'SHA-256 init constants', category: 'crypto', severity: 'low',
    description: 'SHA-256 initial hash values.',
    patterns: [[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb]] },
  { id: 'md5_init', name: 'MD5 init constants', category: 'crypto', severity: 'low',
    description: 'MD5 IV constants (0x67452301…).',
    patterns: [[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]] },
  { id: 'crc32_table', name: 'CRC32 polynomial table', category: 'crypto', severity: 'low',
    description: 'Common CRC32 lookup table prefix.',
    patterns: [[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77]] },
  { id: 'rsa_oid', name: 'RSA OID', category: 'crypto', severity: 'low',
    description: 'PKCS RSA OID 1.2.840.113549.1.1.1',
    patterns: ['\x2a\x86\x48\x86\xf7\x0d\x01\x01'] },

  // === Packers ===
  { id: 'upx', name: 'UPX packer', category: 'packer', severity: 'high',
    description: 'UPX section/marker present.',
    patterns: ['UPX!', 'UPX0', 'UPX1', 'UPX2'] },
  { id: 'vmprotect', name: 'VMProtect', category: 'packer', severity: 'high',
    description: 'VMProtect section signature.',
    patterns: ['.vmp0', '.vmp1', '.vmp2'] },
  { id: 'themida', name: 'Themida', category: 'packer', severity: 'high',
    description: 'Themida packer.',
    patterns: ['.themida', '.taggant'] },
  { id: 'aspack', name: 'ASPack', category: 'packer', severity: 'high',
    description: 'ASPack packer.',
    patterns: ['.aspack', 'ASPack'] },

  // === Compilers / runtimes ===
  { id: 'go_runtime', name: 'Go runtime', category: 'compiler', severity: 'low',
    description: 'Compiled with Go.',
    patterns: ['Go build ID', 'runtime.goexit', 'go.buildid'] },
  { id: 'rust_panic', name: 'Rust runtime', category: 'compiler', severity: 'low',
    description: 'Compiled with Rust.',
    patterns: ['rust_panic', 'core::panicking', '/rustc/'] },
  { id: 'msvc', name: 'MSVC runtime', category: 'compiler', severity: 'low',
    description: 'Microsoft Visual C++ runtime.',
    patterns: ['msvcrt', 'VCRUNTIME', 'Microsoft Visual C++'] },
  { id: 'mingw', name: 'MinGW/GCC', category: 'compiler', severity: 'low',
    description: 'Built with MinGW or GCC.',
    patterns: ['libgcc', 'mingw'] },
  { id: 'nim', name: 'Nim runtime', category: 'compiler', severity: 'low',
    description: 'Compiled with Nim.',
    patterns: ['nimSystem', 'NimMain'] },

  // === Suspicious APIs ===
  { id: 'crypto_apis', name: 'Windows Crypto APIs', category: 'suspicious', severity: 'med',
    description: 'CryptoAPI calls (possible crypto/ransom).',
    patterns: ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'BCryptEncrypt'] },
  { id: 'process_injection', name: 'Process injection APIs', category: 'suspicious', severity: 'high',
    description: 'Common process-injection imports.',
    patterns: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'SetWindowsHookEx'] },
  { id: 'anti_debug', name: 'Anti-debugging', category: 'suspicious', severity: 'high',
    description: 'Anti-debug API calls.',
    patterns: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString'] },
  { id: 'persistence', name: 'Registry persistence', category: 'suspicious', severity: 'high',
    description: 'Registry run-key persistence.',
    patterns: ['Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'CurrentVersion\\RunOnce'] },
  { id: 'network_apis', name: 'Network APIs', category: 'suspicious', severity: 'med',
    description: 'Sockets / HTTP / DNS APIs.',
    patterns: ['WSAStartup', 'InternetOpen', 'HttpSendRequest', 'getaddrinfo', 'WinHttpOpen'] },
  { id: 'shell_exec', name: 'Shell execution', category: 'suspicious', severity: 'med',
    description: 'Process / shell launch.',
    patterns: ['CreateProcess', 'ShellExecute', 'WinExec', 'system'] },

  // === Strings ===
  { id: 'url_http', name: 'HTTP URL', category: 'string', severity: 'low',
    description: 'Embedded HTTP/HTTPS URL.',
    patterns: ['http://', 'https://'] },
  { id: 'ip_v4', name: 'IPv4 dotted literal', category: 'string', severity: 'low',
    description: 'Looks like an embedded IPv4 (partial match).',
    patterns: ['127.0.0.1', '0.0.0.0'] },
  { id: 'sql_keywords', name: 'SQL', category: 'string', severity: 'low',
    description: 'SQL syntax strings present.',
    patterns: ['SELECT ', 'INSERT INTO', 'DROP TABLE'] },

  // === Known bad markers ===
  { id: 'mimikatz', name: 'Mimikatz markers', category: 'malware', severity: 'high',
    description: 'Strings characteristic of Mimikatz.',
    patterns: ['sekurlsa', 'lsadump', 'mimikatz'] },
  { id: 'cobalt', name: 'Cobalt Strike beacon', category: 'malware', severity: 'high',
    description: 'Cobalt Strike beacon strings.',
    patterns: ['beacon.x64.dll', 'beacon.dll', 'i_am_a_real_beacon'] },
]

function bytesOf(p: string | number[]): Uint8Array {
  if (typeof p === 'string') {
    const out = new Uint8Array(p.length)
    for (let i = 0; i < p.length; i++) out[i] = p.charCodeAt(i) & 0xff
    return out
  }
  return new Uint8Array(p)
}

function findAll(haystack: Uint8Array, needle: Uint8Array, max = 8): number[] {
  if (!needle.length) return []
  const out: number[] = []
  const limit = haystack.length - needle.length
  outer: for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    out.push(i)
    if (out.length >= max) break
    i += needle.length - 1
  }
  return out
}

export function scan(data: Uint8Array, rules: Rule[] = RULES): RuleHit[] {
  const hits: RuleHit[] = []
  for (const rule of rules) {
    const offsets: number[] = []
    for (const p of rule.patterns) {
      const found = findAll(data, bytesOf(p))
      for (const f of found) if (!offsets.includes(f)) offsets.push(f)
    }
    if (offsets.length) hits.push({ rule, offsets: offsets.slice(0, 8) })
  }
  return hits
}
