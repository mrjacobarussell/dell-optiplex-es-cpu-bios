# Dell OptiPlex ES CPU BIOS Patch

> ⚠️ **WARNING: ACTIVE DEVELOPMENT — DO NOT USE IN PRODUCTION**
>
> All patches, binaries, and methods described here are experimental.
> Do not flash any BIOS files from this repository without understanding the risks.
> No support is provided. Use at your own risk.

## Status: Testing Stalled

Testing is paused pending available time to continue research. Progress has been made
but the implementation is not yet complete. Check back for updates.

## What Has Been Achieved

- Identified Intel Boot Guard is active on all tested OptiPlex 3060/3070/7060 Micro units
- Confirmed microcode FV (FFD20000) is **outside** the Boot Guard IBB — can be modified
- Confirmed FV_main_A (FF0E1000, 6MB) is **outside** the Boot Guard IBB — PEI injection works
- Confirmed PEI Core dispatches PEIMs from FV_main_A (registered in IBB FV table)
- Successfully bypassed brand string whitelist check via PEI hot-patching (confirmed by LED pattern change)
- QQCO ES chip survives SEC phase with FIT microcode fix
- SA/MRC hang after brand check on 3060 — believed due to 3060 SA/MRC lacking 9th Gen init code
- 3070 patch built and ready to test (3070 SA/MRC supports 9th Gen natively)

## Machines Tested

| Machine | Model | Boot Guard | Status |
|---------|-------|-----------|--------|
| Jeff | OptiPlex 3060 Micro | Active | SA/MRC hang after brand bypass |
| Daryl | OptiPlex 3070 Micro | Active | Production server — not tested |
| Vincent | OptiPlex 7060 | Active | Not tested |
| Spare 3070 | OptiPlex 3070 Micro | Active | Patch built, not yet flashed |
| HP EliteDesk 800 G5 Mini | — | Unknown | Next to test |

## Next Steps

1. Analyze HP EliteDesk 800 G5 Mini — may not have Boot Guard (different manufacturer)
2. Flash and test spare 3070 with built patch
3. Investigate SA/MRC post-brand-check hang if needed

## Documentation

See  for full technical documentation.

---

*Do not use any files from this repo until a stable release is announced.*
