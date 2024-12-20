# -*- coding: utf-8 -*-
import json
import base64
import warnings
import functools
from typing import Callable

def deprecated(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        warnings.warn(
            f"{func.__name__}() is deprecated.",
            DeprecationWarning,
            stacklevel=2
        )
        return func(*args, **kwargs)
    return wrapper

__all__ = ['int_to_bytes', 'bytes_to_int', 'serialize_key', 'deserialize_key']

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, byteorder='big')

def strencode(source: str) -> str:
    """문자열을 base64 문자열로 변환"""
    return base64.b64encode(source.encode('ascii')).decode('ascii')

def strdecode(source: str) -> str:
    """base64 문자열을 원문으로 변환"""
    return base64.b64decode(source.encode('ascii')).decode('ascii')

def byteencode(source: bytes) -> str:
    """비트스트링을 base64 문자열로 변환"""
    return base64.b64encode(source).decode('ascii')

def bytedecode(source: str) -> bytes:
    """base64 문자열을 비트스트링로 변환"""
    return base64.b64decode(source)

@deprecated
def serialize_key(key: dict) -> str:
    return ':'.join(f"{k}:{v}" for k, v in key.items())
# 프로토콜 업데이트 전 사용한 함수입니다

@deprecated
def deserialize_key(key_str: str) -> dict:
    key_dict = {}
    parts = key_str.split(':')
    for i in range(0, len(parts), 2):
        if i + 1 < len(parts):
            key_dict[parts[i]] = int(parts[i+1])
    return key_dict
# 프로토콜 업데이트 전 사용한 함수입니다

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
    
    test_str = "Hello, World!"
    print(f"Original string: {test_str}")
    print(f"Base64 encoded string: {strencode(test_str)}")
    print(f"Base64 decoded string: {strdecode(strencode(test_str))}")