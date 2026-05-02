#!/usr/bin/env python3
"""
Dell OptiPlex 3060 Micro BIOS patcher
Enables Intel i9-9900T ES (QQCO, CPUID 906EC) on BIOS 1.31.0

Usage: python3 patch_3060.py <stock_dump.bin> <output_patched.bin>

The stock dump must be a full 32MB SPI flash image acquired via flashrom
with service mode jumper (JMP1 pins 5-6) and a retail CPU installed.

Official Intel 906EC microcode (intel-ucode/06-9e-0c) must be present
as microcode_906ec_official.bin in the same directory.
"""

import struct
import sys
import os

BIOS_VERSION = "1.31.0"
EXPECTED_SIZE = 0x2000000  # 32MB

# Patch 1: FFS injection of 906EC microcode
FFS_BASE       = 0x1d203e8   # microcode FFS file offset
FFS_HDR_SIZE   = 0x18        # FFS header size
INJECT_OFFSET  = 0x1d54000   # immediately after 906EB (no gap)
NEW_FFS_SIZE   = 0x4dc18     # header(0x18) + 906EA(0x19c00) + 906EB(0x1a000) + 906EC(0x1a000)
UC_906EC_SIZE  = 0x1a000     # Intel official 906EC blob size

# Patch 2: Brand string whitelist bypass
BRAND_PATCH_OFFSET = 0x1e50fee
BRAND_BEFORE = bytes([0x8b, 0x45, 0xf8, 0xeb, 0x11])  # mov eax,[ebp-8]; jmp +0x11
BRAND_AFTER  = bytes([0x31, 0xdb, 0xeb, 0x00, 0x90])   # xor ebx,ebx; jmp +0; nop


def verify_checksum(blob):
    total = sum(struct.unpack_from("<" + "I" * (len(blob) // 4), blob)) & 0xFFFFFFFF
    return total == 0


def patch_microcode_pf(uc_data):
    """Patch 906EC platform flags 0x22 -> 0xFF and recalculate checksum."""
    uc = bytearray(uc_data)
    struct.pack_into("<I", uc, 0x18, 0xFF)
    struct.pack_into("<I", uc, 0x10, 0)
    total = sum(struct.unpack_from("<" + "I" * (len(uc) // 4), uc)) & 0xFFFFFFFF
    struct.pack_into("<I", uc, 0x10, (0x100000000 - total) & 0xFFFFFFFF)
    assert verify_checksum(bytes(uc)), "Microcode checksum verification failed"
    return bytes(uc)


def update_ffs_header(data, ffs_base, new_size):
    """Update FFS file size field and recalculate header checksum."""
    data = bytearray(data)
    # Size is 3 bytes at offset 0x14
    data[ffs_base + 0x14:ffs_base + 0x17] = struct.pack("<I", new_size)[:3]
    # Header checksum at offset 0x10 (byte)
    data[ffs_base + 0x10] = 0
    hdr_sum = sum(data[ffs_base:ffs_base + FFS_HDR_SIZE]) & 0xFF
    data[ffs_base + 0x10] = (0x100 - hdr_sum) & 0xFF
    # Verify
    assert sum(data[ffs_base:ffs_base + FFS_HDR_SIZE]) & 0xFF == 0, \
        "FFS header checksum verification failed"
    return bytes(data)


def patch(stock_path, output_path, microcode_path=None):
    print(f"Reading stock BIOS: {stock_path}")
    with open(stock_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) != EXPECTED_SIZE:
        print(f"ERROR: Expected {EXPECTED_SIZE} bytes, got {len(data)}")
        sys.exit(1)

    # --- Patch 1: Inject 906EC microcode ---
    if microcode_path is None:
        microcode_path = os.path.join(os.path.dirname(__file__), "..", "microcode_906ec_official.bin")
        if not os.path.exists(microcode_path):
            microcode_path = "microcode_906ec_official.bin"

    if not os.path.exists(microcode_path):
        print(f"ERROR: 906EC microcode not found at {microcode_path}")
        print("Download from: https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files")
        print("File: intel-ucode/06-9e-0c")
        sys.exit(1)

    with open(microcode_path, "rb") as f:
        uc906ec_raw = f.read()

    if len(uc906ec_raw) != UC_906EC_SIZE:
        print(f"WARNING: Expected 906EC size {hex(UC_906EC_SIZE)}, got {hex(len(uc906ec_raw))}")

    cpuid = struct.unpack_from("<I", uc906ec_raw, 0x0C)[0]
    if cpuid != 0x906EC:
        print(f"ERROR: Microcode CPUID mismatch: expected 0x906EC, got {hex(cpuid)}")
        sys.exit(1)

    print(f"Patching 906EC platform flags 0x22 -> 0xFF...")
    uc906ec = patch_microcode_pf(uc906ec_raw)

    print(f"Injecting 906EC at {hex(INJECT_OFFSET)}...")
    data[INJECT_OFFSET:INJECT_OFFSET + len(uc906ec)] = uc906ec

    print(f"Updating FFS header (new size: {hex(NEW_FFS_SIZE)})...")
    data = bytearray(update_ffs_header(bytes(data), FFS_BASE, NEW_FFS_SIZE))

    # Verify FFS walk
    pos = FFS_BASE + FFS_HDR_SIZE
    entries = []
    while pos < FFS_BASE + NEW_FFS_SIZE:
        hv = struct.unpack_from("<I", data, pos)[0]
        if hv != 1:
            print(f"  FFS walk stopped at {hex(pos)} (hdr_ver={hex(hv)})")
            break
        cpuid_e = struct.unpack_from("<I", data, pos + 0x0C)[0]
        pf = struct.unpack_from("<I", data, pos + 0x18)[0]
        total = struct.unpack_from("<I", data, pos + 0x20)[0]
        cksum = sum(struct.unpack_from("<" + "I" * (total // 4), data, pos)) & 0xFFFFFFFF
        entries.append((hex(pos), hex(cpuid_e), hex(pf), cksum == 0))
        pos += total

    for off, cpuid_s, pf_s, ok in entries:
        status = "OK" if ok else "CHECKSUM FAIL"
        print(f"  Entry {off}: CPUID={cpuid_s} pf={pf_s} checksum={status}")

    if len(entries) != 3:
        print(f"ERROR: Expected 3 microcode entries, found {len(entries)}")
        sys.exit(1)
    if not all(ok for _, _, _, ok in entries):
        print("ERROR: One or more microcode checksum failures")
        sys.exit(1)

    # --- Patch 2: Brand string bypass ---
    print(f"Applying brand string bypass at {hex(BRAND_PATCH_OFFSET)}...")
    actual = bytes(data[BRAND_PATCH_OFFSET:BRAND_PATCH_OFFSET + 5])
    if actual != BRAND_BEFORE:
        print(f"ERROR: Brand patch location mismatch")
        print(f"  Expected: {BRAND_BEFORE.hex()}")
        print(f"  Found:    {actual.hex()}")
        sys.exit(1)
    data[BRAND_PATCH_OFFSET:BRAND_PATCH_OFFSET + 5] = BRAND_AFTER
    print(f"  {BRAND_BEFORE.hex()} -> {BRAND_AFTER.hex()}")

    print(f"Writing patched BIOS: {output_path}")
    with open(output_path, "wb") as f:
        f.write(data)

    print("Done. All patches applied successfully.")
    print()
    print("Next steps:")
    print("  1. Boot Jeff with retail i3-8100T in service mode (JMP1 pins 5-6)")
    print(f"  2. flashrom_static -p internal -w {output_path}")
    print("  3. Shut down, swap i3 -> QQCO, move JMP1 to pins 3-4, boot")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 patch_3060.py <stock_dump.bin> <output.bin> [microcode.bin]")
        sys.exit(1)
    mc = sys.argv[3] if len(sys.argv) > 3 else None
    patch(sys.argv[1], sys.argv[2], mc)
