# -*- coding: ascii -*-

import json
import base64
import socket

__all__ = ['create_message', 'parse_message', 'send_message', 'receive_message', 'create_error_message', 'handle_error_message']

def create_message(opcode: int, msg_type: str, **kwargs) -> dict:
    pass

def parse_message(json_str: str) -> dict:
    pass

def send_message(sock: socket.socket, message: dict) -> None:
    pass

def receive_message(sock: socket.socket) -> dict:
    pass

def create_error_message(error_type: str) -> dict:
    pass

def handle_error_message(error_message: dict) -> None:
    pass

if __name__ == "__main__":
    pass