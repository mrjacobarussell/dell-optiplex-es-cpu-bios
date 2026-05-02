#!/usr/bin/env python3
"""
Dell OptiPlex 3070 Micro BIOS patcher
Enables Intel i9-9900T ES (QQCO, CPUID 906EC) on BIOS 1.35.0

Usage: python3 patch_3070.py <stock_dump.bin> <output_patched.bin>
"""

import struct
import sys

BIOS_VERSION = "1.35.0"
EXPECTED_SIZE = 0x2000000  # 32MB

# Patch 1a: First 906EC microcode entry — platform flags
UC1_CHECKSUM_OFFSET = 0x1D54010
UC1_FLAGS_OFFSET    = 0x1D54018
UC1_OLD_CHECKSUM    = bytes.fromhex("5EBA5575")
UC1_NEW_CHECKSUM    = bytes.fromhex("81B95575")
UC1_OLD_FLAGS       = bytes.fromhex("22000000")
UC1_NEW_FLAGS       = bytes.fromhex("FF000000")

# Patch 1b: Second 906EC microcode entry — platform flags
UC2_CHECKSUM_OFFSET = 0x1D6E010
UC2_FLAGS_OFFSET    = 0x1D6E018
UC2_OLD_CHECKSUM    = bytes.fromhex("A0F15575")
UC2_NEW_CHECKSUM    = bytes.fromhex("C3F05575")
UC2_OLD_FLAGS       = bytes.fromhex("22000000")
UC2_NEW_FLAGS       = bytes.fromhex("FF000000")

# Patch 2: Brand string whitelist bypass
BRAND_PATCH_OFFSET = 0x1E551DB
BRAND_BEFORE = bytes([0x8b, 0x45, 0xf8, 0xeb, 0x11])
BRAND_AFTER  = bytes([0x31, 0xdb, 0xeb, 0x00, 0x90])


def apply_patch(data, offset, before, after, name):
    actual = bytes(data[offset:offset + len(before)])
    if actual != before:
        print(f"ERROR: {name} mismatch at {hex(offset)}")
        print(f"  Expected: {before.hex()}")
        print(f"  Found:    {actual.hex()}")
        return False
    data[offset:offset + len(after)] = after
    print(f"  {name}: {before.hex()} -> {after.hex()}")
    return True


def patch(stock_path, output_path):
    print(f"Reading stock BIOS: {stock_path}")
    with open(stock_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) != EXPECTED_SIZE:
        print(f"ERROR: Expected {EXPECTED_SIZE} bytes, got {len(data)}")
        sys.exit(1)

    print("Applying microcode platform flags patches...")
    ok = True
    ok &= apply_patch(data, UC1_CHECKSUM_OFFSET, UC1_OLD_CHECKSUM, UC1_NEW_CHECKSUM, "UC1 checksum")
    ok &= apply_patch(data, UC1_FLAGS_OFFSET, UC1_OLD_FLAGS, UC1_NEW_FLAGS, "UC1 platform flags")
    ok &= apply_patch(data, UC2_CHECKSUM_OFFSET, UC2_OLD_CHECKSUM, UC2_NEW_CHECKSUM, "UC2 checksum")
    ok &= apply_patch(data, UC2_FLAGS_OFFSET, UC2_OLD_FLAGS, UC2_NEW_FLAGS, "UC2 platform flags")

    print("Applying brand string bypass...")
    ok &= apply_patch(data, BRAND_PATCH_OFFSET, BRAND_BEFORE, BRAND_AFTER, "brand string bypass")

    if not ok:
        print("ERROR: One or more patches failed. Is this the right BIOS version?")
        sys.exit(1)

    print(f"Writing patched BIOS: {output_path}")
    with open(output_path, "wb") as f:
        f.write(data)

    print("Done. All patches applied successfully.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 patch_3070.py <stock_dump.bin> <output.bin>")
        sys.exit(1)
    patch(sys.argv[1], sys.argv[2])
