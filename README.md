# Dell OptiPlex ES CPU BIOS Patch

Reverse engineering documentation and binary patching tools to enable the Intel i9-9900T Engineering Sample (QDF: QQCO, CPUID 906EC) on Dell OptiPlex 3060 and 3070 Micro systems.

## The Problem

Inserting an ES i9-9900T into a Dell OptiPlex 3060 or 3070 results in a **3-2 amber LED blink** ("CPU failure") approximately 20 seconds after power-on. Two independent BIOS mechanisms cause this — both must be fixed.

## Root Causes

| # | Cause | Mechanism | Fix |
|---|-------|-----------|-----|
| 1 | Microcode platform flags mismatch | SEC loader checks MSR 0x17 Platform ID against microcode Platform Flags. ES chip reports platform_id=0; stock 906EC flags only cover platforms 1 and 5 (0x22). | Patch flags to 0xFF (match all). On 3060: inject 906EC microcode entirely (not present in stock). |
| 2 | CPU brand string whitelist | SA/MRC init module rejects CPUs whose brand string doesn't match a 12-entry retail prefix table. ES string "Genuine Intel(R) CPU 0000 @ 1.70GHz" matches none. | Patch no-match fallback to return i9 category code. |

## Key Findings

- The SEC loader on both boards **ignores the FIT table** for microcode loading. It uses a hardcoded FV base address (`0xFFD20000`) and scans the FFS file directly.
- The FFS iterator **stops at the first non-microcode byte** (header_version ≠ 1). Injected microcode must be placed immediately after existing entries — not after padding.
- The brand string whitelist is in an **uncompressed PE32 module**, making it directly patchable.

## Supported Hardware

| Board | Chipset | BIOS Analyzed | Status |
|-------|---------|---------------|--------|
| Dell OptiPlex 3070 Micro | H370 | 1.35.0 | ✅ Patched & tested |
| Dell OptiPlex 3060 Micro | Q370 | 1.31.0 | ✅ Patched, pending test |
| Dell OptiPlex 7060 (Vincent) | Q370 | — | 🔲 Analysis pending |
| HP EliteDesk 800 G5 Mini | — | — | 🔲 Not started |

## Files

| File | Description |
|------|-------------|
| `whitepaper.md` | Full technical write-up: SEC loader analysis, IFR findings, all patch offsets |
| `hidden_features_3060.md` | Hidden BIOS settings discovered via IFR/HII analysis |
| `scripts/patch_3060.py` | Python script to produce the patched 3060 BIOS from a stock dump |
| `scripts/patch_3070.py` | Python script to produce the patched 3070 BIOS from a stock dump |
| `scripts/verify.py` | Verify an existing patch file against expected byte changes |

## Quick Start

```bash
# Requirements: Python 3, flashrom (service mode)

# 1. Dump your stock BIOS (service mode jumper required, retail CPU in socket)
./flashrom_static -p internal -r stock.bin

# 2. Apply patches
python3 scripts/patch_3060.py stock.bin patched.bin   # for 3060
python3 scripts/patch_3070.py stock.bin patched.bin   # for 3070

# 3. Flash
./flashrom_static -p internal -w patched.bin

# 4. Shut down, swap to ES CPU, remove service mode jumper, boot
```

## Hardware Notes

- **3060 and newer**: BIOS chip is **SOIC-16, 300 mil** — requires SOIC-16 clip and adapter
- **Pre-3060 (3070, 7060, etc.)**: SOIC-8 chip
- CH341A programmer: must use **3.3V step-down mod** (stock outputs 5V, will damage chip)
- Socketing: SOIC-16 to DIP-16 adapter + machined-pin DIP socket = easy chip swaps

## Credits

Reverse engineering by Flynne + Claude (May 2026).
