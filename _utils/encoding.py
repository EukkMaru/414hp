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

__all__ = ['int_to_bytes', 'bytes_to_int', 'strencode', 'strdecode', 'byteencode', 'bytedecode']

def int_to_bytes(x: int) -> bytes:
    pass

def bytes_to_int(xbytes: bytes) -> int:
    pass

def strencode(source: str) -> str:
    """문자열을 base64 문자열로 변환"""
    pass

def strdecode(source: str) -> str:
    """base64 문자열을 원문으로 변환"""
    pass

def byteencode(source: bytes) -> str:
    """비트스트링을 base64 문자열로 변환"""
    pass

def bytedecode(source: str) -> bytes:
    """base64 문자열을 비트스트링로 변환"""
    pass

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
    pass