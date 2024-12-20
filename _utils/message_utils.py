# -*- coding: ascii -*-

import json
import base64
import socket
import logging

__all__ = ['create_message', 'parse_message', 'send_message', 'receive_message', 'create_error_message', 'handle_error_message']

def create_message(opcode: int, msg_type: str, **kwargs) -> dict:
    message = {
        "opcode": opcode,
        "type": msg_type
    }
    for key, value in kwargs.items():
        message[key] = value
    return message

def parse_message(json_str: str) -> dict:
    message = json.loads(json_str)
    # for key in ['public', 'private', 'encryption']:
    #     if key in message:
    #         message[key] = base64.b64decode(message[key]).decode('ascii')
    return message

def send_message(sock: socket.socket, message: dict) -> None:
    json_str = json.dumps(message)
    sock.sendall(json_str.encode())

def receive_message(sock: socket.socket) -> dict:
    data = sock.recv(4096)
    parsed = parse_message(data.decode())
    logging.info(f"Connection received: {parsed}")
    return parsed

def create_error_message(error_type: str) -> dict:
    return create_message(3, "error", error=error_type)

def handle_error_message(error_message: dict) -> None:
    print(f"Error: {error_message['error']}")

if __name__ == "__main__":
    test_message = create_message(1, "RSA", public="test_public_key", parameter={"p": 61, "q": 53})
    print("Created message:", test_message)
    
    json_str = json.dumps(test_message)
    parsed_message = parse_message(json_str)
    print("Parsed message:", parsed_message)

    error_msg = create_error_message("incorrect prime number")
    print("Error message:", error_msg)
    handle_error_message(error_msg)

    # Note: We can't test send_message and receive_message here
    # as they require an actual socket connection.
    print("Note: send_message and receive_message functions require an actual socket connection to test.")