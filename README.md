# Dell OptiPlex ES CPU BIOS Patch

> ⚠️ **WARNING: ACTIVE DEVELOPMENT — DO NOT USE IN PRODUCTION**
>
> This project is currently in active testing and research. All patches, binaries,
> and methods described here are experimental and may brick your machine.
> Do not flash any BIOS files from this repository without understanding the risks.
> No support is provided. Use at your own risk.

## Project Status

**IN TESTING** — We are actively reverse engineering Boot Guard bypass methods
for Coffee Lake Dell OptiPlex machines. Current approach uses PEI module injection
into an unprotected firmware volume (FV_main_A) to patch the brand string whitelist
check at runtime. This is NOT a stable or ready-to-use patch.

## Goal

Enable the Intel i9-9900T Engineering Sample (QDF: QQCO, CPUID 906EC) on Dell
OptiPlex 3060 and 3070 Micro systems which have Intel Boot Guard active.

## Documentation

See  for full technical documentation including reverse engineering
findings, Boot Guard analysis, and the PEI injection approach.

---

*Do not use any files from this repo until a stable release is announced.*
