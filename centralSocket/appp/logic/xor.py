def xor_bytes(byte_str1, byte_str2):
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))
