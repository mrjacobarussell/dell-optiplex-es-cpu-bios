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

### BIOS Chip Package Notes

| Generation | Package | Programmer Clip |
|---|---|---|
| Pre-3060 era (3070, 7060, etc.) | SOIC-8, ~150/208 mil | SOIC-8 clip |
| 3060 and newer | **SOIC-16, 300 mil** | **SOIC-16 clip** |

For repeated flashing without disassembly: solder a SOIC-16 to DIP-16 adapter in place of the chip, insert chip in machined-pin DIP-16 socket. Pop out for bench programming, reinsert to run.

**CH341A voltage**: Stock CH341A outputs 5V. BIOS chips are 3.3V. Always use the 3.3V step-down mod board.

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
| `bios_dump.bin` | Original 3070 flash dump (Jeff, historical) |
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
