<div align="center">

# ⚡ CGTWIF — GPU Bitcoin WIF Search 

**cryptographytube** · Author: **Sisujhon**

*CUDA-accelerated recovery of Bitcoin private keys from a partially-known WIF.*

![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![CUDA](https://img.shields.io/badge/CUDA-12.x%2B-76B900?logo=nvidia&logoColor=white)
![GPU](https://img.shields.io/badge/GPU-sm__75%20%E2%86%92%20sm__120-76B900)
![Language](https://img.shields.io/badge/C%2B%2B%2FCUDA-%2300599C?logo=cplusplus&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)

</div>

---

CUDA-accelerated Bitcoin private-key search engines that brute-force **unknown characters** in a WIF (Wallet Import Format) string. Two independent GPU engines, one shared host-side elliptic-curve library, and a Python range-splitter that feeds them.

```
                       ┌─────────────────────────────┐
   hex range           │  wifrange.py (Python)       │        WIF start/end tails
   1000..1fff ───────► │  split into N subparts,     │ ────────────────────────────►
                       │  print WIF range per part   │                              │
                       └─────────────────────────────┘                              ▼
                                                                    ┌───────────────────────────────────┐
                                                                    │ CGTWIF_Scanner  (GPU engine #1)   │
                                                                    │ CGTWIF_Reaper   (GPU engine #2)   │
                                                                    │   fill the ? in the WIF mask,     │
                                                                    │   checksum-filter, EC-derived     │
                                                                    │   address, match against btc.txt  │
                                                                    └───────────────────────────────────┘
```

---

## What it does

Given a WIF mask with unknown characters written as `?` (Scanner) or `X`/`?`/`*`/`.` (Reaper), the engines enumerate the unknown tail in **Base58 order**, run the WIF checksum gate, and for every checksum-valid key derive the compressed/uncompressed address and test it against your address list.

The checksum gate is the whole trick: only **1 in 2³²** candidates survives the cheap double-SHA256 test, so the expensive EC multiplication + address hash only ever runs on survivors.

```
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7r???????????          <- mask (11 unknowns)
        │                                └ 11 × Base58 digits each, filled by the engine
        └ fixed prefix (known)
```

- `-start` / `-end` restrict the fill to an inclusive Base58 range — **this is where the Python splitter output goes**.
- Range < 2⁶⁴ → sequential sweep; add `-r` for random sampling of a wider keyspace (full cover, no repeats).

---

## Features

| | Engine #1 — `CGTWIF_Scanner` | Engine #2 — `CGTWIF_Reaper` |
|---|---|---|
| Technique | Delta odometer (12×58×320-bit pre-baked deltas in `__constant__`, kernel only adds) | Horner walker (one 320-bit weight per slot, shift-and-multiply in registers) |
| Constant memory | ~34 KB | ~500 bytes (lives in broadcast cache) |
| Grid layout | 1-D | 2-D: `blockIdx.y` selects coarse digits, no divide-by-58 in the hot path |
| Checksum | SHA256d short-circuit (first output word only — just the 4 checksum bytes matter) | Same |
| Hit collection | `__ballot_sync` + warp-leader atomic | Same |
| Max unknowns (sequential) | `CGT_SLOTS` | 10 |
| Max unknowns (with `-r`) | `RND_MAX` | `RP_MAX` |

Both binaries are built as a **multi-arch fatbin**: `sm_75`, `sm_86`, `sm_89`, `sm_120` (plus PTX `compute_120`) — one `.exe` runs on GTX 16-series through RTX 50-series.

---

## Requirements

- **Windows 10/11** (x64)
- **Visual Studio 2022** (or 2019) with *Desktop development with C++* workload
- **CUDA Toolkit 12.x+** on PATH (`nvcc`)
- **NVIDIA GPU**: GTX 1660+ (`sm_75`), RTX 20/30 (`sm_86`), RTX 40 (`sm_89`), RTX 50 (`sm_120`)
- **Python 3.x** (only for the range splitter scripts)

---

## Build

Double-click `build.bat` — or run it from a terminal:

```bat
build.bat
```

What it does:

1. Locates `vcvars64.bat` (VS 2022 Community/Professional/Enterprise, falls back to 2019).
2. Compiles the host library (`cryptographytube/lib/…`) and both `.cu` engines **in a single `nvcc` invocation each** — no intermediate `.obj` step, no `obj/` folder.
3. Produces `CGTWIF_Scanner.exe` and `CGTWIF_Reaper.exe` in the project root.

```
=== engine 1: CGTWIF_Scanner ===
CGTWIF_Scanner.cu
Int.cpp
IntMod.cpp
Point.cpp
SECP256K1.cpp
util.cpp
sha256.cpp
ripemd160.cpp
base58.c
=== engine 2: CGTWIF_Reaper ===
...

  BUILD OK
```

---

## Usage

### CGTWIF_Scanner

```
CGTWIF_Scanner <mask> [-d dev] [-btc btc.txt] [-out found.txt]
              [-hit wifaddfound.txt] [-q] [-r]
              [-start <tail>] [-end <tail>]
```

| Option | Meaning |
|---|---|
| `<mask>` | WIF with unknown chars as `?` (also `*` `.`). First positional arg or via `-mask`. |
| `-d <n>` | CUDA device index (default `0`). |
| `-btc <file>` / `-f <file>` | Address list to match against (default `btc.txt`; `-f` is a keyhunt-style alias). |
| `-out <file>` | Append every checksum-valid WIF here (default `found.txt`). |
| `-hit <file>` | Full hit record: WIF + hex privkey + both addresses (default `wifaddfound.txt`). |
| `-start` / `-end` | Base58 fill range, one char per unknown. **Must both be given**; `start ≤ end`. |
| `-r` | Random sampling — needed when keyspace > 2⁶⁴ or unknowns > slot cap. |
| `-q` | Quiet — don't print every checksum-valid key. |

**Examples**

```bat
:: scan a single subpart handed to you by wifrange.py
CGTWIF_Scanner.exe KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7r??????????? ^
    -start 9Ko6iP3cMU -end oiRV7thtwU -r

:: full sequential sweep of an 8-unknown mask
CGTWIF_Scanner.exe KwDiBf89QgGbjEhKnhXJ?H7LrciVrZ?3qYjgd9M7?FU73sVHnoWn

:: quiet run, custom address list
CGTWIF_Scanner.exe "L?????x3FA5LXz8uQ9k7BdPM85FTrZJom9mdNGtmTtgwt5KATfh" -btc my.txt -q
```

**Note:** `-start`/`-end` are compared as Base58 numbers — the first character carries the most weight (`1 < 9 < A < Z < a < z`). Put the smaller value in `-start`, or you'll get `ERROR: -start value is greater than -end`.

### CGTWIF_Reaper

```
CGTWIF_Reaper <mask> [-d dev] [-btc btc.txt] [-out found.txt]
              [-hit wifaddfound.txt] [-q] [-r]
```

Same options as the Scanner (no `-start`/`-end`; unknowns as `X` `?` `*` `.`). Use `-r` for more than 10 unknowns or keyspaces > 2⁶⁴.

```bat
CGTWIF_Reaper.exe "L*****x3FA5LXz8uQ9k7BdPM85FTrZJom9mdNGtmTtgwt5KATfh"
```

---

## Live run

A real session on an **RTX 5070 Ti** — 10 unknowns, random sweep of a 4.5-quadrillion keyspace at **842 Gkey/s**, finding a checksum-valid WIF:

```console
$ CGTWIF_Scanner.exe KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF?????????? -start UiD4boGJim -end VKNFdmhPA9 -r

  ============================================================
      CGTWIF_Scanner   -   GPU engine #1  (delta odometer)
      cryptographytube      |      Author: Sisujhon
  ============================================================
  GPU        : NVIDIA GeForce RTX 5070 Ti  (sm_120, 70 SMs)
  Mask       : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF??????????
  Mode       : COMPRESSED (38-byte payload)
  Sampling   : RANDOM (-start..-end range, every combo once, exits)
  Unknowns   : 10  @ 43,44,45,46,47,48,49,50,51,52
  Range      : UiD4boGJim .. VKNFdmhPA9
  Keyspace   : 4502499768229785  (random order, full cover, exits at end)
  found.txt  : found.txt
  hits       : wifaddfound.txt   (btc list: btc.txt)
  ------------------------------------------------------------

  Loaded 6 addresses from btc.txt

  [    2.9s]   0.05%  covered 2.438e+12 / 4.502e+15    842.36 Gkey/s   valid 0  match 0
  [VALID] KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUsGvEAcbBb
    comp   16KsqPs76YbNtL8w9XggM62NLza2cDugBE
    uncomp 1Gc74hqTmQTPj57G9vAdz4jgaB1y4qXnv3
    hex    0000000000000000000000000000000000000000000000000000000000001420
```

**Reading the banner:**

| Line | Meaning |
|---|---|
| `GPU` | Detected device, compute capability, SM count. |
| `Mask` | Your WIF with `?` marking the unknowns. |
| `Mode` | Compressed (52-char, 38-byte payload) or uncompressed (51-char, 37-byte). |
| `Sampling` | `RANDOM` (`-r`) covers every combo once then exits; `SEQUENTIAL` walks in order. |
| `Unknowns` | Count and the exact positions being filled. |
| `Range` | The `-start .. -end` Base58 window. |
| `Keyspace` | Total candidates in the range. |
| Progress line | Elapsed, % covered, candidates done / total, **Gkey/s**, checksum-valid count, btc.txt matches. |
| `[VALID]` | A checksum-valid WIF — printed with both addresses and the hex private key, and appended to `found.txt`. |

---

## Workflow: hex range → WIF range → GPU scan

The Python range-splitter turns a **hex private-key range** into the exact `-start`/`-end` WIF tails the engines consume. No hex-64 scan needed — you split, the engine enumerates the WIF suffix.

### `wifrange.py` — Range Splitter with GLOBAL WIF RANGE Analysis

**Recommended for most users.** This is the primary range-splitting tool.

```bat
python wifrange.py
```

Prompts for a start/end hex range and a part count (1–1000), then:

1. **GLOBAL WIF RANGE ANALYSIS** — shows the entire range's WIF span, common prefix length, and unique tails (start/end). This is where you see the mask pattern for the whole keyspace.
2. **Per-subpart output** — each part prints:
   - start/end in decimal and 64-char hex
   - **WIF range (compressed)** — global common prefix + unique suffix of both ends
   - first / middle / last key: int, hex, WIF uncompressed, WIF compressed

**Example output:**

```
======================================================================
CRYPTOGRAPHYTUBE - Range Splitter with GLOBAL WIF Range
======================================================================

Enter Start Range (hex): 1000
Enter End Range (hex): 1fff

======================================================================
Range
START : 0000000000000000000000000000000000000000000000000000000000001000
END   : 0000000000000000000000000000000000000000000000000000000000001FFF
TOTAL : 4096 keys
======================================================================

How many subparts (1-1000): 10

======================================================================
GLOBAL WIF RANGE ANALYSIS
======================================================================
Global Start WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUiD4boGJim
Global End WIF:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFVKNFdmhPA9
Global Common Prefix: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF
Prefix Length: 42 chars

Global Start Unique (RED): UiD4boGJim
Global End Unique (RED):   VKNFdmhPA9

Full Global Range:
  KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUiD4boGJim
  ->
  KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFVKNFdmhPA9

======================================================================
CRYPTOGRAPHYTUBE - SPLIT RESULTS
======================================================================

CRYPTOGRAPHYTUBE
PART 1:
  Start (dec): 4096
  Start (hex): 0000000000000000000000000000000000000000000000000000000000001000
  End   (dec): 4505
  End   (hex): 0000000000000000000000000000000000000000000000000000000000001199
  WIF RANGE (compressed):
    Global Common Prefix: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF
    Start Unique (RED):   UiD4boGJim
    End Unique (RED):     UmijUJEHHC
    Full Range:
      KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUiD4boGJim
      ->
      KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUmijUJEHHC
  FIRST KEY:
    int: 4096
    hex: 0000000000000000000000000000000000000000000000000000000000001000
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrn8m4JvW9
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUiD4boGJim
  MIDDLE KEY:
    int: 4301
    hex: 00000000000000000000000000000000000000000000000000000000000010cd
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrnXtUrvFz
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUjy9Suw1sE
    MIDDLE WIF RANGE:
      Common Prefix: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF
      Middle Unique (YELLOW): Ujy9Suw1sE
      Full Middle WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUjy9Suw1sE
  LAST KEY:
    int: 4505
    hex: 0000000000000000000000000000000000000000000000000000000000001199
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrnvtqZv5i
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUmijUJEHHC
----------------------------------------------------------------------

CRYPTOGRAPHYTUBE
PART 2:
  Start (dec): 4506
  Start (hex): 000000000000000000000000000000000000000000000000000000000000119a
  End   (dec): 4915
  End   (hex): 0000000000000000000000000000000000000000000000000000000000001333
  WIF RANGE (compressed):
    Global Common Prefix: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF
    Start Unique (RED):   UmjEJc28pn
    End Unique (RED):     UqEu7kaubB
    Full Range:
      KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUmjEJc28pn
      ->
      KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUqEu7kaubB
  FIRST KEY:
    int: 4506
    hex: 000000000000000000000000000000000000000000000000000000000000119a
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsrnw3sB2Ea
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUmjEJc28pn
  MIDDLE KEY:
    int: 4711
    hex: 0000000000000000000000000000000000000000000000000000000000001267
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsroL8Q6TvD
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUoVK7w6oVo
    MIDDLE WIF RANGE:
      Common Prefix: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF
      Middle Unique (YELLOW): UoVK7w6oVo
      Full Middle WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUoVK7w6oVo
  LAST KEY:
    int: 4915
    hex: 0000000000000000000000000000000000000000000000000000000000001333
    wif uncompressed: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsroj94LTaq
    wif compressed:   KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUqEu7kaubB
----------------------------------------------------------------------
```

**Feeding the engine.** Every part's WIF range collapses into a mask + two tails. The global common prefix becomes the fixed part of the mask, and the unique suffixes become the `-start` / `-end` range:

```
mask   = KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF??????????
-start = UiD4boGJim      (global start unique)
-end   = VKNFdmhPA9      (global end unique)
```

```bat
CGTWIF_Scanner.exe KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rF?????????? ^
    -start UiD4boGJim -end VKNFdmhPA9 -r
```

> The GLOBAL WIF RANGE ANALYSIS block gives you exactly what the mask needs: the **common prefix** is the fixed part, and the **start/end unique** tails are your `-start`/`-end`. Keep the number of `?` equal to the length of those tails (here 10 chars → 10 `?`, since a compressed WIF is 52 chars and the prefix is 42).

---

## Output files

| File | Content |
|---|---|
| `found.txt` | Every checksum-valid WIF found (append mode), printed per line. |
| `wifaddfound.txt` | Full record on a btc.txt hit: `WIF`, `PRIVKEY_HEX`, `ADDR_COMP`, `ADDR_UNCOMP`. |
| `btc.txt` | Your input address list — one address per line, matched against both compressed and uncompressed. |

Console hit example:

```
  [VALID] KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFUiD4boGJim
    comp   bc1q… 
    uncomp 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    hex    0000000000000000000000000000000000000000000000000000000000001000
```

---

## Repository layout

```
├── CGTWIF_Scanner.cu        GPU engine #1 — delta odometer
├── CGTWIF_Reaper.cu         GPU engine #2 — Horner walker
├── build.bat                one-click build (VS + CUDA)
├── wifrange.py              hex range splitter → GLOBAL WIF range + per-part tails
├── btc.txt                  address watch-list
└── cryptographytube/
    └── lib/                 host library: big-int, secp256k1, sha256, ripemd160, base58
```

---

## License

Provided for **educational and research purposes** — for example, recovering keys you own, auditing WIF-format strength, or studying GPU parallelism. Only use it on keys and ranges you are legally entitled to search. The author assumes no responsibility for misuse.
