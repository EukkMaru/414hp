 #! PLEASE DO NOT USE NON-ASCII CHARACTERS (KOREAN) IN server.py AND client.py

import socket
import threading
import argparse
import logging
import json
import base64

from _utils import rsa_utils as rsa
from _utils import dh_utils as dh
from _utils import symmetric as sym
from _utils import math_utils as math
from _utils import encoding as encoding
from _utils import message_utils as messaging

public_key, private_key, p, q = None, None, None, None

def initialize():
    global public_key, private_key, p, q

    public_key, private_key, p, q = rsa.generate_rsa_keypair()

def handle_protocol_1(conn):
    logging.info("Initiating protocol 1: RSA Key Generation")
    global public_key, private_key, p, q
    initialize()
    
    response = messaging.create_message(0, "RSAKey", 
                                        private=encoding.serialize_key(private_key),
                                        public=encoding.serialize_key(public_key),
                                        parameter={"p": str(p), "q": str(q)})
    logging.debug(f"Sending response: {response}")
    messaging.send_message(conn, response)

def handle_protocol_2(conn):
    global public_key, private_key, p, q
    
    response = messaging.create_message(1, "RSA", 
                                        public=encoding.serialize_key(public_key),
                                        parameter={"n": str(public_key['n'])})
    logging.debug(f"Sending RSA response: {response}")
    messaging.send_message(conn, response)

    key_message = messaging.receive_message(conn)
    if key_message['opcode'] != 2 or key_message['type'] != "RSA":
        logging.error("Unexpected message from client")
        return

    encrypted_key = base64.b64decode(key_message['encryption'])
    logging.debug(f"Received Encrypted key: {encrypted_key}")
    aes_key = rsa.rsa_decrypt(encrypted_key, private_key, True)
    logging.debug(f"Decrypted AES key: {aes_key}")

    # AES message exchange
    aes_message = messaging.receive_message(conn)
    if aes_message['opcode'] != 2 or aes_message['type'] != "AES":
        logging.error("Unexpected message from client")
        return
    
    logging.debug(f"Received AES message: {aes_message}")
    decrypted_message = sym.aes_decrypt(aes_key, aes_message['encryption'])
    logging.info(f"Received decrypted message: {decrypted_message.decode('ascii')}")

    response_message = "Server Response Message"
    encrypted_response = sym.aes_encrypt(aes_key, response_message.encode('ascii'))
    response = messaging.create_message(2, "AES", encryption=encrypted_response)
    messaging.send_message(conn, response)

def handle_protocol_3(conn):
    p, g = dh.generate_dh_params(2048)  # Use appropriate bit length
    logging.debug(f"p: {p}, g: {g}")
    private_key, public_key = dh.generate_dh_keypair(p, g)
    logging.debug(f"Private key: {private_key}\n Public key: {public_key}")
    
    response = messaging.create_message(1, "DH", 
                                        public=encoding.serialize_key({'key': public_key}),
                                        parameter={"p": str(p), "g": str(g)})
    logging.debug(f"Sending RSA response: {response}")
    messaging.send_message(conn, response)

    client_response = messaging.receive_message(conn)
    if client_response['opcode'] != 1 or client_response['type'] != "DH":
        logging.error("Unexpected message from client")
        return

    client_public = int(encoding.deserialize_key(client_response['public'])['key'])
    shared_secret = dh.compute_dh_shared_secret(private_key, client_public, p)
    aes_key = sym.generate_aes_key_from_dh(shared_secret)

    # AES message exchange
    aes_message = messaging.receive_message(conn)
    if aes_message['opcode'] != 2 or aes_message['type'] != "AES":
        logging.error("Unexpected message from client")
        return

    decrypted_message = sym.aes_decrypt(aes_key, aes_message['encryption'])
    logging.info(f"Received decrypted message: {decrypted_message.decode('ascii')}")

    response_message = "Hello from server (DH)!"
    encrypted_response = sym.aes_encrypt(aes_key, response_message.encode())
    response = messaging.create_message(2, "AES", encryption=encrypted_response)
    messaging.send_message(conn, response)

def handle_protocol_4_1(conn):
    # DH with non-prime error
    non_prime = 100  # An obviously non-prime number for demonstration
    g = 2
    response = messaging.create_message(1, "DH", 
                                        public=encoding.serialize_key({'key': 1}),
                                        parameter={"p": str(non_prime), "g": str(g)})
    messaging.send_message(conn, response)

    error_message = messaging.receive_message(conn)
    if error_message['opcode'] == 3 and error_message['type'] == "error":
        logging.info(f"Received expected error: {error_message['error']}")
    else:
        logging.error("Did not receive expected error message")

def handle_protocol_4_2(conn):
    # DH with incorrect generator error
    p = dh.generate_prime(1024)  # Generate a prime number
    incorrect_g = p  # Using p as g, which is not a proper generator
    response = messaging.create_message(1, "DH", 
                                        public=encoding.serialize_key({'key': 1}),
                                        parameter={"p": str(p), "g": str(incorrect_g)})
    messaging.send_message(conn, response)

    error_message = messaging.receive_message(conn)
    if error_message['opcode'] == 3 and error_message['type'] == "error":
        logging.info(f"Received expected error: {error_message['error']}")
    else:
        logging.error("Did not receive expected error message")

def handler(sock):
    try:
        while True:
            try:
                message = messaging.receive_message(sock)
                logging.info(f"Received message: {message}")
                if message['opcode'] == 0:
                    if message['type'] == "RSAKey":
                        handle_protocol_1(sock)
                    elif message['type'] == "RSA":
                        handle_protocol_2(sock)
                    elif message['type'] == "DH":
                        handle_protocol_3(sock)
            except json.JSONDecodeError as e:
                logging.error(f"JSON Decode Error: {e}")
            except Exception as e:
                logging.error(f"Error handling message: {e}")
    except Exception as e:
        logging.error(f"Error handling connection: {e}")
    finally:
        sock.close()


def run(addr, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))

    server.listen(10)
    logging.info("[*] Server is listening on {}:{}".format(addr, port))

    while True:
        conn, info = server.accept()

        logging.info("[*] Server accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn,))
        conn_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<server's IP address>", help="server's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<server's open port>", help="server's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()