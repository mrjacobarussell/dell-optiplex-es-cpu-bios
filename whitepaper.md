# Enabling ES/QS Engineering Sample CPUs on Dell OptiPlex Micro Systems
## A Technical White Paper — Revision 2

**Author:** Reverse Engineering Session — Flynne + Claude  
**Original Date:** April 2026  
**Revision Date:** May 2026  
**Target Hardware:**  
- Dell OptiPlex 3070 Micro (Intel H370, LGA1151) — BIOS 1.35.0  
- Dell OptiPlex 3060 Micro (Intel Q370, LGA1151) — BIOS 1.31.0  

---

## Abstract

Dell OptiPlex 3060 and 3070 Micro systems ship with Intel 8th/9th generation Coffee Lake processors. Retail 9th generation CPUs work in these systems after a standard microcode injection. However, Engineering Sample (ES) variants — such as the i9-9900T QDF QQCO (CPUID 906EC) — fail with a 3-2 amber LED blink pattern despite sharing identical CPUID signatures with retail parts.

This paper documents the complete reverse engineering process for both the 3060 (Q370) and 3070 (H370) variants, identifying two independent root causes common to both boards and the binary patches that resolve them. A third challenge unique to the 3060 — the complete absence of 906EC microcode — required a FFS injection approach not needed for the 3070.

---

## 1. Background and Motivation

### 1.1 The Opportunity

The Intel i9-9900T ES (QDF: QQCO) is a pre-production Coffee Lake Refresh processor available on secondary markets for $20–40 USD versus $150+ for the retail variant. Both are physically identical silicon on LGA1151 with 8 cores / 16 threads at 35W TDP. For small form factor home lab clusters, this represents a compelling upgrade path.

### 1.2 The Problem

Inserting an ES i9-9900T into a Dell OptiPlex 3060 or 3070 Micro results in a 3-2 amber LED blink pattern approximately 20 seconds after power-on. Standard CPUID microcode injection does not resolve the failure on either board.

### 1.3 ES Chip Distinguishing Characteristics

| Property | Retail (i5-9500T / i9-9900T) | ES (i9-9900T QQCO) |
|---|---|---|
| CPUID | 0x000906EC | 0x000906EC |
| Stepping | P0 / R0 | Pre-production P0 |
| MSR 0x17 Platform ID | Non-zero (bits 1,5 → 0x22) | 0 (all bits clear) |
| CPU Brand String | "Intel(R) Core(TM) i9-9900T..." | "Genuine Intel(R) CPU 0000 @ 1.70GHz" |
| Microcode Platform Flags | 0x22 | 0x01 (1 << platform_id=0) |
| Base Clock | 2.1 GHz | ~1.7 GHz (typical ES) |
| Max Turbo | 4.4 GHz | ~3.8–4.4 GHz (varies) |

---

## 2. Tools and Methodology

### 2.1 Tools

- **flashrom v1.8.0** — SPI flash read/write via Intel service mode jumper (JMP1 pins 5-6)
- **UEFIExtract** — UEFI firmware volume and FFS file extraction
- **Python 3** — Binary patching, checksum calculation, FFS structure parsing
- **capstone / manual disassembly** — x86 analysis of BIOS binary regions

### 2.2 Flash Acquisition

Service mode (JMP1 pins 5-6) was enabled and the full 32MB SPI flash was read from each machine with a retail CPU installed:

```bash
./flashrom_static -p internal -r bios_dump.bin
```

Flash layout (32MB):
- `0x000000–0x000FFF`: Intel Flash Descriptor
- `0x001000–0x00FFFF`: Intel ME region (start)
- `0x1000000–0x1FFFFFF`: BIOS region (16MB)

### 2.3 Board Differences

| Feature | OptiPlex 3070 Micro | OptiPlex 3060 Micro |
|---|---|---|
| Board | 02N3WF | — |
| Chipset | H370 | Q370 |
| BIOS Version Analyzed | 1.35.0 | 1.31.0 |
| 906EC Microcode Present | Yes (platform_flags=0x22) | **No** — must inject |
| SEC Loader Method | FFS scan (hardcoded FV base) | FFS scan (hardcoded FV base) |
| Microcode FV Address | 0xFFD20000 | 0xFFD20000 |
| Microcode FFS GUID | 72850817-7F37-EF44... | 72850817-7F37-EF44... |
| BIOS Chip Package | SOIC-8 (older) | **SOIC-16, 300 mil** |

---

## 3. Root Cause Analysis — Common to Both Boards

### 3.1 Root Cause 1 — Microcode Platform Flags Mismatch

#### 3.1.1 SEC Phase Microcode Loader

Both boards use the same SEC phase microcode loading strategy. Contrary to common assumption, the SEC loader does **not** read the Intel Firmware Interface Table (FIT) to locate microcode. Confirmed by:

1. No reference to the FIT pointer address (0xFFFFFFC0) in either board's SEC code
2. Presence of `_FVH` signature check in SEC code at a hardcoded FV base address

The loader:
1. Loads hardcoded base address `0xFFD20000` into a register (`mov ebx, 0xFFD20000`)
2. Validates the FV header (`_FVH` at base+0x28)
3. Walks FFS files within the FV
4. For each FFS file, iterates concatenated microcode entries (header_version == 1)
5. For each entry: reads CPU Platform ID from MSR 0x17 bits[52:50], computes bitmask `1 << platform_id`, checks `test [entry+0x18], bitmask`
6. Selects highest-revision matching entry and loads via MSR 0x79

Key disassembly (3060, physical ~0xFFFFEBDA region):
```asm
mov   ebx, 0xFFD20000       ; hardcoded microcode FV base
...
cmp   dword ptr [edx+0x28], '_FVH'  ; validate FV header
...
rdmsr                        ; read MSR 0x17 (platform ID)
shr   edx, 0x12
and   dl, 7                  ; extract 3-bit platform ID
mov   cl, dl
mov   dl, 1
shl   dl, cl                 ; dl = 1 << platform_id (bitmask)
...
cmp   [ebx], 1               ; header version check (stops at 0xFF)
jne   skip                   ; invalid entry, skip
...
test  byte ptr [ebx+0x18], dl  ; platform flag match?
```

**Critical**: The FFS iterator stops when it encounters `header_version != 1`. Free space (0xFF bytes) between microcode entries will halt the scan. Microcode entries must be concatenated without gaps.

#### 3.1.2 Why ES Chips Fail

The ES QQCO reports Platform ID = 0. Bitmask = `1 << 0 = 0x01`. Stock 906EC microcode has Platform Flags = 0x22. `0x22 & 0x01 = 0` → no match → microcode not loaded.

#### 3.1.3 Fix — Platform Flags Patch

Change the 906EC microcode Platform Flags field from `0x22` to `0xFF` (match all platforms). Recalculate the Intel microcode header checksum (sum of all 32-bit dwords must equal zero).

**3070 (BIOS 1.35.0) — flags patch only:**

| Field | SPI Offset | Before | After |
|---|---|---|---|
| Header Checksum | 0x1D54010 | 5E BA 55 75 | 81 B9 55 75 |
| Platform Flags | 0x1D54018 | 22 00 00 00 | FF 00 00 00 |

*Note: The 3070 BIOS contained two 906EC entries. Both required patching.*

**3060 (BIOS 1.31.0) — FFS injection (no 906EC present):**

The 3060 BIOS contains only 906EA and 906EB microcodes. 906EC must be injected. The official Intel microcode blob (CPUID 906EC, rev 0xF8, 0x1A000 bytes) was sourced from the Intel Linux Processor Microcode Data Files repository (`intel-ucode/06-9e-0c`).

FFS structure before patch:
```
FFS file at 0x1d203e8 (size 0x35c28):
  906EA at 0x1d20400  size=0x19c00  pf=0x22
  906EB at 0x1d3a000  size=0x1a000  pf=0x02
  [0x2010 bytes of 0xFF padding]     ← FFS ends here
```

FFS structure after patch:
```
FFS file at 0x1d203e8 (size 0x4dc18):
  906EA at 0x1d20400  size=0x19c00  pf=0x22
  906EB at 0x1d3a000  size=0x1a000  pf=0x02
  906EC at 0x1d54000  size=0x1a000  pf=0xFF  ← injected (replaces padding)
```

**Important**: 906EC must be placed at `0x1d54000` (immediately after 906EB), not after the 0xFF padding. The SEC loader stops iteration on the first `header_version != 1` byte. Placing the injection after padding would make it invisible to the loader.

FFS changes:
- Size field at `0x1d203f8` (3 bytes): `0x35c28` → `0x4dc18`
- Header checksum at `0x1d203f8` recalculated
- 906EC blob written to `0x1d54000` with platform_flags patched `0x22 → 0xFF`
- 906EC header checksum recalculated (dword sum = 0 verified)

---

### 3.2 Root Cause 2 — CPU Brand String Whitelist

#### 3.2.1 Discovery

Despite the microcode fix, the 3-2 blink persisted on both boards. String search across all extracted UEFI modules revealed the error string in both boards' SA/MRC initialization module:

```
"CPU Brand String Not Supported"
```

This module is stored **uncompressed** in the main firmware volume on both boards and runs during PEI phase approximately 20 seconds into POST.

#### 3.2.2 Brand String Whitelist Structure

Both boards contain an identical 12-entry whitelist table (50 bytes per entry: 48-byte prefix string + 2-byte CPU category code):

| Index | Brand String Prefix | Category Code |
|---|---|---|
| 0 | Intel(R) Core(TM) i9 | 0x00CF |
| 1 | Intel(R) Core(TM) i7 | 0x00C6 |
| 2 | Intel(R) Core(TM) i5 | 0x00CD |
| 3 | Intel(R) Core(TM) i3 | 0x00CE |
| 4–7 | Intel(R) Core(TM) m3/m5/m7/M | 0x002D–0x002C |
| 8 | Intel(R) Pentium(R) | 0x000B |
| 9 | Intel(R) Celeron(R) | 0x000F |
| 10 | Intel(R) Atom(TM) | 0x002B |
| 11 | Intel(R) Xeon(R) | 0x00B3 |

The ES brand string "Genuine Intel(R) CPU 0000 @ 1.70GHz" matches none of these entries.

#### 3.2.3 Comparison Loop

The loop iterates all 12 entries (loop bound: `cmp [ebp-4], 0x258` — 12 × 50 = 600 = 0x258). On no-match, a fallback path loads an error value and returns, triggering the 3-2 blink.

No-match fallback (identical pattern on both boards):
```asm
; No match found:
mov eax, [ebp-8]    ; load error/default value  ← PATCH HERE
jmp return
; Match found:
imul ebx, ebx, 0x32 ; multiply entry index by 50
movzx eax, word ptr [ebx + table_addr]  ; read category code
jmp return
```

#### 3.2.4 Fix — Whitelist Bypass Patch

Patch the no-match fallback to set entry index to 0 (i9) and fall through to the found path:

```
Before: 8B 45 F8 EB 11   (mov eax,[ebp-8]; jmp +0x11)
After:  31 DB EB 00 90   (xor ebx,ebx; jmp +0; nop)
```

Effect: When no brand string matches, ebx=0 → imul 0*50=0 → reads i9 category code (0x00CF) → returns successfully. Boot continues.

**Offsets by board:**

| Board | BIOS Version | SPI Flash Offset |
|---|---|---|
| 3070 Micro | 1.35.0 | 0x1E551DB |
| 3060 Micro | 1.31.0 | 0x1E50FEE |

---

## 4. FIT Table vs FFS Scanning

### 4.1 Intel Firmware Interface Table (FIT)

Both boards have a FIT table. The 3060's FIT at dump offset `0x1D20100` contains explicit entries for 906EA and 906EB microcodes.

**However:** Neither board's SEC loader uses the FIT for microcode selection. This was verified by:
1. Searching the last 64KB of the BIOS (SEC loader region) for the FIT pointer address (physical `0xFFFFFFC0`)
2. Finding zero references to that address in either board's SEC code
3. Confirming the SEC loader uses a hardcoded `mov reg, 0xFFD20000` to load the microcode FV base directly

This means FIT-based microcode injection approaches (adding new FIT entries) will not work on these boards. The only effective injection point is within the FFS file at the hardcoded FV base.

### 4.2 Implication

The FIT entries for 906EA and 906EB on the 3060 appear to be present for ACM/TXT purposes or as legacy artifacts, not for SEC microcode loading. Our FFS injection bypasses the FIT entirely and is the correct approach.

---

## 5. Patch Summaries

### 5.1 Dell OptiPlex 3070 Micro — BIOS 1.35.0

**File:** `bios_patched_v5.bin`

| Patch | SPI Offset | Before | After | Purpose |
|---|---|---|---|---|
| Microcode pf (entry 1) checksum | 0x1D54010 | 5E BA 55 75 | 81 B9 55 75 | Checksum for pf change |
| Microcode pf (entry 1) flags | 0x1D54018 | 22 00 00 00 | FF 00 00 00 | ES platform match |
| Microcode pf (entry 2) checksum | 0x1D6E010 | A0 F1 55 75 | C3 F0 55 75 | Checksum for pf change |
| Microcode pf (entry 2) flags | 0x1D6E018 | 22 00 00 00 | FF 00 00 00 | ES platform match |
| Brand string bypass | 0x1E551DB | 8B 45 F8 EB 11 | 31 DB EB 00 90 | Skip whitelist rejection |

### 5.2 Dell OptiPlex 3060 Micro — BIOS 1.31.0

**File:** `bios_3060_patched_v3.bin`

| Patch | SPI Offset | Before | After | Purpose |
|---|---|---|---|---|
| FFS header checksum | 0x1D203F8 | EC | D9 | Updated for size change |
| FFS size field | 0x1D203FD–FF | 28 3C 05 | 18 DC 04 | Extended for 906EC |
| 906EC blob (0x1A000 bytes) | 0x1D54000 | FF×0x1A000 | Intel microcode | New microcode entry |
| 906EC platform flags | 0x1D54018 | 22 00 00 00 | FF 00 00 00 | ES platform match |
| Brand string bypass | 0x1E50FEE | 8B 45 F8 EB 11 | 31 DB EB 00 90 | Skip whitelist rejection |

---

## 6. Flashing Procedure

### Prerequisites
- Service mode jumper engaged: JMP1 pins 5-6
- System booted to OS with a working retail CPU in socket
- flashrom_static binary available

### Full Flash
```bash
# Always backup first
./flashrom_static -p internal -r backup_$(date +%Y%m%d).bin

# Flash patched BIOS
./flashrom_static -p internal -w bios_3060_patched_v3.bin
# Expected: "Verifying flash... VERIFIED."

# Shut down, swap retail CPU for ES QQCO, move JMP1 back to pins 3-4, boot
```



### ROM Recovery Header — Emergency External Flashing

If the BIOS becomes unbootable (bad flash, incompatible patch), the 3060 Micro exposes a hardware SPI recovery header that allows direct external programming without disassembly or chip clips.

```
         ROM_RECOVERY HEADER (8-pin, 2.54mm)

              +--------+
    GND   7 --| o  o |-- 8  SPI_CLK
   3VSB   5 --| o  o |-- 6  SPI_MISO
     NC   3 --|    o |-- 4  SPI_MOSI
 SPI_CS#  1 --| o  o |-- 2  SPI_CS#  <- factory jumper (see below)
              +--------+

  Pin 3 is physically absent (no pin).
  Factory jumper bridges pins 1-2 for normal PCH operation.
```

#### CH341A Wiring (6-wire method, board unplugged)

| ROM Header Pin | Signal   | CH341A BIOS SPI Pin |
|----------------|----------|---------------------|
| 1              | SPI_CS#  | 1 (CS)              |
| 4              | SPI_MOSI | 5 (MOSI)            |
| 5              | 3VSB/VCC | 8 (VCC)             |
| 6              | SPI_MISO | 2 (MISO)            |
| 7              | GND      | 4 (GND)             |
| 8              | SPI_CLK  | 6 (CLK)             |

**Procedure:**
1. Remove the factory jumper from pins 1-2
2. Wire the 6 connections above
3. Unplug the machine from the wall (PCH must be completely dead)
4. Plug CH341A into host USB (CH341A supplies 3.3V to chip via VCC pin)
5. Ensure CH341A mode jumper is on 1-2 (USB ID 1a86:5512)

```bash
# Probe -- should detect W25Q256JV_Q (32MB, 3.3V)
./flashrom_static -p ch341a_spi -c W25Q256JV_Q

# Restore stock BIOS
./flashrom_static -p ch341a_spi -c W25Q256JV_Q -w bios_stock_v1.31.0.bin
# Expected: "Verifying flash... VERIFIED."
```

6. Remove all wires, reinstall factory jumper on pins 1-2, plug machine back in

**BIOS chip:** Winbond W25Q256JVFQ — SOIC-16, 300 mil, **3.3V**. Do not use 1.8V adapter.

### BIOS Chip Package Notes

| Generation | Package | Programmer Clip |
|---|---|---|
| Pre-3060 era (3070, 7060, etc.) | SOIC-8, ~150/208 mil | SOIC-8 clip |
| 3060 and newer | **SOIC-16, 300 mil** | **SOIC-16 clip** |

For repeated flashing without disassembly: solder a SOIC-16 to DIP-16 adapter in place of the chip, insert chip in machined-pin DIP-16 socket. Pop out for bench programming, reinsert to run.

**CH341A voltage**: The 3060 BIOS chip (W25Q256JVFQ) runs at **3.3V**. Do not use a 1.8V adapter. If using a clip directly on the chip, use the 3.3V step-down mod on the CH341A. When using the ROM recovery header, the board supplies its own 3.3V via the 3VSB pin (machine plugged in) or the CH341A supplies 3.3V directly (machine unplugged, VCC wired).

---

## 7. Why Retail 9th Gen Works But ES Does Not

A retail i9-9900T brand string matches whitelist entry 0. A retail i5-9500T matches entry 2. Both pass.

The QQCO brand string begins with "Genuine" — matching none of the 12 prefixes. This explains why the same ES chip works on consumer B365M/Z390 boards (no whitelist) but fails on corporate Dell H370/Q370 boards (whitelist present in Dell-specific BIOS modules).

---

## 8. Applicability to Other Systems

### Dell OptiPlex 5060 / 7060 (Q370 chipset)
Same generation, same BIOS architecture. The two root causes are expected to be present. The 7060 will require:
- Independent offset analysis (different BIOS image)
- Likely the same FFS injection approach as the 3060 if 906EC microcode is absent
- Independent brand string whitelist offset identification

Preliminary dump available: `bios_dump_vincent.bin`

### Dell OptiPlex 3060/3070 SFF and Tower
Same chipset and BIOS image as Micro variants. Patches apply at identical offsets for the same BIOS version.

### BIOS Version Changes
Both patches are offset-specific to the analyzed BIOS versions. A BIOS update requires:
1. Re-identifying the microcode FFS entry (GUID search + FFS walk)
2. Re-identifying the brand string table (`Intel(R) Core(TM) i9` string search)
3. Recomputing offsets, sizes, and checksums

---

## 9. Conclusion

Two independent BIOS mechanisms block ES i9-9900T chips on Dell OptiPlex 3060/3070 systems:

1. **Microcode platform flags** — SEC loader checks MSR 0x17 platform bits against microcode Platform Flags. ES chips report platform_id=0; affected microcodes cover only platforms 1 and 5 (flags=0x22). Fixed by setting flags to 0xFF in the FFS-resident microcode blob(s). On the 3060, 906EC microcode is entirely absent and must be injected from Intel's official source.

2. **CPU brand string whitelist** — SA/MRC module rejects CPUs whose brand string does not match a 12-entry retail prefix table. Fixed by patching the no-match return path to return the i9 category code instead of an error.

---

## Appendix A — File Locations (Daryl, 192.168.0.13:/mnt/cache/bios_flash/)

| File | Description |
|---|---|
| `bios_dump.bin` | Original 3060 flash dump (Jeff, pre-patch) |
| `bios_stock_v1.31.0.bin` | 3060 stock flash dump (Jeff) |
| `bios_3060_patched_v3.bin` | 3060 patched BIOS — ready to flash |
| `bios_patched_v5.bin` | 3070 patched BIOS — flashed to Jeff previously |
| `bios_dump_vincent.bin` | 7060 flash dump (Vincent) — analysis pending |
| `microcode_906ec_official.bin` | Intel official 906EC microcode (rev 0xF8) |
| `flashrom_static` | Static flashrom binary |
| `whitepaper.md` | This document |

## Appendix B — Key BIOS Module GUIDs

| GUID | Description | Board |
|---|---|---|
| 17088572-377F-44EF-8F4E-B09FFF46A070 | Microcode FFS file | 3070 |
| 728508177F37EF44... | Microcode FFS file | 3060 |
| 299D6F8B-2EC9-4E40-9EC6-DDAA7EBF5FD9 | SA/MRC init — brand string whitelist | 3070 |
| (3060 equivalent — PE32 at 0x1E44240) | SA/MRC init — brand string whitelist | 3060 |
| E9DD7F62-25EC-4F9D-A4AB-AAD20BF59A10 | DellBeepInitializeStatusCode — LED blink handler | Both |

## Appendix C — SEC Loader Analysis

The SEC loader in both boards:
- Lives in the last ~64KB of the BIOS image (high physical addresses)
- Hardcodes the microcode FV base as `0xFFD20000`
- Validates `_FVH` signature at FV base + 0x28
- Iterates concatenated microcode blobs within FFS content by reading `total_size` from each header
- Stops iteration when `header_version != 1` (e.g., 0xFF padding bytes)
- Checks CPUID and platform flags before loading
- Loads via WRMSR 0x79

**The FIT table is irrelevant for microcode loading on these boards.** FIT entries for microcode are present but ignored by the SEC loader.


## Appendix D — CPU Compatibility Notes for 3060 Patch

### Removed Microcode: CPUID 906EA

The 3060 patch (`bios_3060_patched_v5.bin`) removes the 906EA microcode entry to
make room for 906EC within the existing FFS without changing the FFS size or structure.

**CPUs that lose microcode updates (CPUID 906EA, Coffee Lake A0 stepping):**
- Intel Core i7-8700K, i7-8700
- Intel Core i5-8600K, i5-8400
- Intel Core i3-8100 (non-T desktop)
- Intel Pentium Gold G5400, G5500, G5600
- Intel Celeron G4900, G4920, G4930, G4950

**Why this is safe for OptiPlex 3060 Micro users:**
All T-variant CPUs sold for the OptiPlex 3060 Micro form factor (i3-8100T, i5-8400T,
i5-8500T, i5-8600T, i7-8700T) use CPUID 906EB, which is retained. The 906EA CPUs
are predominantly K-series enthusiast desktop parts incompatible with the Micro's
power delivery and form factor.

### Why the FFS size cannot be extended

The microcode FFS (GUID 17088572) resides in FV AFDD39F1 alongside other files:

| Offset     | File                | Size     | Description        |
|------------|---------------------|----------|--------------------|
| 0x1D20000  | FV header           | 0x78h    | Volume header      |
| 0x1D203E8  | 17088572 (microcode)| 0x35C28  | Microcode FFS      |
| 0x1D56010  | PAD file            | 0xFD8    | Alignment padding  |
| 0x1D56FE8  | 2D27C618            | 0x2D6D8  | Critical raw file  |
| 0x1D84EC0  | Volume free space   | —        |                    |

Extending the FFS size past 0x35C28 consumes the PAD file and overwrites 2D27C618,
causing an immediate brick. All previous failed patches (v3, v4) had this root cause.

### Microcode layout in v5 (FFS size 0x35C28, UNCHANGED):
| Entry  | Offset in FFS | Size    | Platform Flags | Notes              |
|--------|---------------|---------|----------------|--------------------|
| 906EC  | 0x1D20400     | 0x19FD0 | 0xFF (patched) | ES chip support    |
| 906EB  | 0x1D3A3D0     | 0x19FD0 | 0x02 (stock)   | i3/i5/i7 T-series  |
| 0xFF   | 0x1D543A0     | 0x1C70  | —              | Padding            |


## Appendix E — Boot Guard Analysis and PEI Injection Approach

### E.1 Intel Boot Guard Status

All tested OptiPlex machines have Boot Guard fully provisioned:

| Machine | Board | Boot Guard |
|---------|-------|-----------|
| Jeff    | OptiPlex 3060 Micro | Active (ACM + KM + BP) |
| Daryl   | OptiPlex 3070 Micro | Active |
| Vincent | OptiPlex 7060       | Active |

**Intel ME version:** 12.0.97.3000 (Coffee Lake ME 12.x — post SA-00086 patch window)

Boot Guard failure signature: 1 white blink + 1 amber blink → immediate shutdown (enforcement mode).

Any modification to the IBB (Initial Boot Block) causes this failure. The IBB covers:
- FV_microcode (FFD20000–FFD2FFFF): microcode FV
- FV_PEI (FFE10000–FFEFFFFFF): all PEI modules including SA/MRC brand check
- FV_SEC (FFF00000–FFFFFFFF): SEC code, reset vector, ACM

### E.2 Firmware Volume Map

| Item | Base (chip) | Physical | Size | IBB? | Contents |
|------|------------|----------|------|------|----------|
| NVRAM1 | 0x1000000 | FF000000 | 256KB | No | UEFI variables |
| NVRAM2 | 0x1040000 | FF040000 | 256KB | No | UEFI variables backup |
| FV_small | 0x1080000 | FF080000 | 68KB | No | Config data |
| FV_cfg | 0x10D1000 | FF0D1000 | 64KB | No | Freeform data |
| **FV_main_A** | **0x10E1000** | **FF0E1000** | **6MB** | **No** | **EMPTY — injection target** |
| FV_main_B | 0x16E1000 | FF6E1000 | 6.2MB | No | DXE drivers (LZMA compressed) |
| FV_empty | 0x1D10000 | FFD10000 | 64KB | ? | Empty |
| FV_microcode | 0x1D20000 | FFD20000 | 960KB | **YES** | Microcode FFS |
| FV_PEI | 0x1E10000 | FFE10000 | 960KB | **YES** | All PEI modules |
| FV_SEC | 0x1F00000 | FFF00000 | 1MB | **YES** | SEC, PEI Core, ACM |

### E.3 PEI Injection via FV_main_A

**Key discovery:** The IBB SEC FV (FFF00000) contains a FV registration table (FREEFORM file, GUID 173C1CC9-74FC-E546-BDBE-6F486A5A9F3C) that explicitly registers FV_main_A (38301D13-7D54-4E65-AC50-782DB7F0E29A) for PEI Core to scan. PEI Core will dispatch PEIMs from FV_main_A.

**SA/MRC dispatch dependencies (DEPEX):**
SA/MRC (299D6F8B-2EC9-4E40-9EC6-DDAA7EBF5FD9) depends on 4 PPIs that must be installed before it runs. This creates a window for our injected PEIM to register a notification callback before SA/MRC executes.

**Planned injection approach:**
1. Build a minimal UEFI PEIM (PE32 binary)
2. PEIM entry point registers a notify callback on EFI_PEI_PERMANENT_MEMORY_INSTALLED_PPI
3. When SA/MRC installs memory, callback fires within SA/MRC execution context
4. Callback scans PEI memory for brand check bytes (8B 45 F8 EB 11) with context
5. Patches to bypass (31 DB EB 00 90)
6. SA/MRC continues with patched code → brand check passes
7. PEIM is wrapped in FFS PEIM file and placed in FV_main_A (empty, outside IBB)

**Status:** Build environment being prepared (Docker container with GCC on Daryl).

### E.4 Microcode Strategy

Since the microcode FV is IBB-protected, 906EC microcode cannot be injected into BIOS. Alternative: OS-level microcode loading via Unraid's early microcode path (/lib/firmware/intel-ucode/06-9e-0c). This loads after POST completes but before userspace, providing microcode for stable operation.
