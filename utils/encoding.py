# -*- coding: utf-8 -*-

__all__ = ['int_to_bytes', 'bytes_to_int', 'serialize_key', 'deserialize_key']

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, byteorder='big')

def serialize_key(key: dict) -> str:
    return ':'.join(f"{k}:{int_to_bytes(v).hex()}" for k, v in key.items())

def deserialize_key(key_str: str) -> dict:
    key_dict = {}
    for item in key_str.split(':'):
        if not item:
            continue
        if ':' in item:
            k, v = item.split(':')
            key_dict[k] = bytes_to_int(bytes.fromhex(v))
    return key_dict

if __name__ == "__main__":
    original_int = 123456789
    byte_string = int_to_bytes(original_int)
    recovered_int = bytes_to_int(byte_string)
    print(f"Original int: {original_int}")
    print(f"Byte string: {byte_string}")
    print(f"Recovered int: {recovered_int}")
    print(f"Conversion successful: {original_int == recovered_int}")

    original_key = {'n': 1234567890, 'e': 65537}
    serialized = serialize_key(original_key)
    deserialized = deserialize_key(serialized)
    print(f"\nOriginal key: {original_key}")
    print(f"Serialized key: {serialized}")
    print(f"Deserialized key: {deserialized}")
    print(f"Serialization successful: {original_key == deserialized}")