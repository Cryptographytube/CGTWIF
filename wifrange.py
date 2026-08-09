#!/usr/bin/env python3
"""
CRYPTOGRAPHYTUBE - Range Splitter with GLOBAL WIF Range Display
Global common prefix + MIDDLE KEY in YELLOW
"""

import hashlib

# Color codes
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data):
    num = int.from_bytes(data, 'big')
    encode = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encode = B58_ALPHABET[rem] + encode
    for byte in data:
        if byte == 0:
            encode = '1' + encode
        else:
            break
    return encode

def base58_check_encode(data):
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

def int_to_hex256(n):
    return f"{n:064x}"

def int_to_bytes32(n):
    return n.to_bytes(32, 'big')

def private_key_to_wif_uncompressed(key_int):
    key_bytes = int_to_bytes32(key_int)
    extended = b'\x80' + key_bytes
    return base58_check_encode(extended)

def private_key_to_wif_compressed(key_int):
    key_bytes = int_to_bytes32(key_int)
    extended = b'\x80' + key_bytes + b'\x01'
    return base58_check_encode(extended)

def hex_to_int(hex_str):
    hex_str = hex_str.strip().replace("0x", "").replace(" ", "")
    return int(hex_str, 16)

def find_common_prefix(str1, str2):
    min_len = min(len(str1), len(str2))
    for i in range(min_len):
        if str1[i] != str2[i]:
            return str1[:i]
    return str1[:min_len]

def main():
    print("=" * 70)
    print("CRYPTOGRAPHYTUBE - Range Splitter with GLOBAL WIF Range")
    print("=" * 70)

    # Input Start Range (hex)
    while True:
        try:
            start_hex = input("\nEnter Start Range (hex): ").strip()
            start = hex_to_int(start_hex)
            if start > 0:
                break
        except:
            pass
        print("Invalid start range!")

    # Input End Range (hex)
    while True:
        try:
            end_hex = input("Enter End Range (hex): ").strip()
            end = hex_to_int(end_hex)
            if end >= start:
                break
            else:
                print("End must be >= Start!")
        except:
            pass
        print("Invalid end range!")

    # Show range info
    print("\n" + "=" * 70)
    print("Range")
    print(f"START : {start:064X}")
    print(f"END   : {end:064X}")
    print(f"TOTAL : {end - start + 1} keys")
    print("=" * 70)

    # Input number of parts
    while True:
        try:
            parts = int(input("\nHow many subparts (1-1000): "))
            if 1 <= parts <= 1000:
                break
        except:
            pass
        print("Invalid number!")

    # Calculate segments
    total_size = end - start + 1
    size = total_size // parts
    rem = total_size % parts

    # First pass: calculate all parts and store data
    parts_data = []
    current = start

    for i in range(parts):
        seg_size = size
        if i < rem:
            seg_size += 1

        seg_start = current
        seg_end = current + seg_size - 1
        seg_middle = seg_start + (seg_size // 2)

        parts_data.append({
            'label': "last" if i == parts - 1 else str(i + 1),
            'seg_start': seg_start,
            'seg_end': seg_end,
            'seg_middle': seg_middle,
            'start_wif_comp': private_key_to_wif_compressed(seg_start),
            'end_wif_comp': private_key_to_wif_compressed(seg_end),
            'start_wif_unc': private_key_to_wif_uncompressed(seg_start),
            'end_wif_unc': private_key_to_wif_uncompressed(seg_end),
            'middle_wif_comp': private_key_to_wif_compressed(seg_middle),
            'middle_wif_unc': private_key_to_wif_uncompressed(seg_middle),
        })

        current = seg_end + 1

    # Calculate GLOBAL common prefix from overall range start/end WIF
    global_start_wif = parts_data[0]['start_wif_comp']
    global_end_wif = parts_data[-1]['end_wif_comp']
    global_common = find_common_prefix(global_start_wif, global_end_wif)

    print("\n" + "=" * 70)
    print("GLOBAL WIF RANGE ANALYSIS")
    print("=" * 70)
    print(f"Global Start WIF: {global_start_wif}")
    print(f"Global End WIF:   {global_end_wif}")
    print(f"Global Common Prefix: {global_common}")
    print(f"Prefix Length: {len(global_common)} chars")

    # Show global unique parts
    global_start_unique = global_start_wif[len(global_common):]
    global_end_unique = global_end_wif[len(global_common):]
    print(f"\nGlobal Start Unique (RED): {RED}{global_start_unique}{RESET}")
    print(f"Global End Unique (RED):   {RED}{global_end_unique}{RESET}")
    print(f"\nFull Global Range:")
    print(f"  {global_common}{RED}{global_start_unique}{RESET}")
    print(f"  ->")
    print(f"  {global_common}{RED}{global_end_unique}{RESET}")

    print("\n" + "=" * 70)
    print("CRYPTOGRAPHYTUBE - SPLIT RESULTS")
    print("=" * 70)

    # Second pass: display all parts with global common prefix
    for part in parts_data:
        # Calculate unique parts relative to GLOBAL common prefix
        start_unique = part['start_wif_comp'][len(global_common):]
        end_unique = part['end_wif_comp'][len(global_common):]
        middle_unique = part['middle_wif_comp'][len(global_common):]

        print(f"\nCRYPTOGRAPHYTUBE")
        print(f"PART {part['label']}:")
        print(f"  Start (dec): {part['seg_start']}")
        print(f"  Start (hex): {int_to_hex256(part['seg_start'])}")
        print(f"  End   (dec): {part['seg_end']}")
        print(f"  End   (hex): {int_to_hex256(part['seg_end'])}")

        # WIF RANGE DISPLAY using GLOBAL common prefix
        print(f"  WIF RANGE (compressed):")
        print(f"    Global Common Prefix: {global_common}")
        print(f"    Start Unique (RED):   {RED}{start_unique}{RESET}")
        print(f"    End Unique (RED):     {RED}{end_unique}{RESET}")
        print(f"    Full Range:")
        print(f"      {global_common}{RED}{start_unique}{RESET}")
        print(f"      ->")
        print(f"      {global_common}{RED}{end_unique}{RESET}")

        # FIRST KEY
        print(f"  FIRST KEY:")
        print(f"    int: {part['seg_start']}")
        print(f"    hex: {int_to_hex256(part['seg_start'])}")
        print(f"    wif uncompressed: {part['start_wif_unc']}")
        print(f"    wif compressed:   {part['start_wif_comp']}")

        # MIDDLE KEY with WIF range breakdown in YELLOW
        print(f"  MIDDLE KEY:")
        print(f"    int: {part['seg_middle']}")
        print(f"    hex: {int_to_hex256(part['seg_middle'])}")
        print(f"    wif uncompressed: {part['middle_wif_unc']}")
        print(f"    wif compressed:   {part['middle_wif_comp']}")
        print(f"    MIDDLE WIF RANGE:")
        print(f"      Common Prefix: {global_common}")
        print(f"      Middle Unique (YELLOW): {YELLOW}{middle_unique}{RESET}")
        print(f"      Full Middle WIF: {global_common}{YELLOW}{middle_unique}{RESET}")

        # LAST KEY
        print(f"  LAST KEY:")
        print(f"    int: {part['seg_end']}")
        print(f"    hex: {int_to_hex256(part['seg_end'])}")
        print(f"    wif uncompressed: {part['end_wif_unc']}")
        print(f"    wif compressed:   {part['end_wif_comp']}")

        print("-" * 70)

    print("\n" + "=" * 70)
    print("CRYPTOGRAPHYTUBE - COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
