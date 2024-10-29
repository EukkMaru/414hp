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

args = None

# public_key, private_key, p, q = None, None, None, None

# def initialize():
#     global public_key, private_key, p, q

#     public_key, private_key, p, q = rsa.generate_rsa_keypair()

def handle_protocol_1(conn):
    logging.info("Initiating protocol 1: RSA Key Generation")
    public_key, private_key, p, q = rsa.generate_rsa_keypair()
    # initialize()
    logging.info(f"Generated RSA keypair: public={public_key}, private={private_key}, p={p}, q={q}")
    
    response = messaging.create_message(0, "RSAKey", 
                                        private=private_key,
                                        public=public_key,
                                        parameter={"p": p, "q": q})
    logging.debug(f"Sending response: {response}")
    messaging.send_message(conn, response)

def handle_protocol_2(conn):
    public_key, private_key, p, q = rsa.generate_rsa_keypair()
    
    response = messaging.create_message(1, "RSA", 
                                        public=public_key,
                                        parameter={"n": p * q})
    logging.debug(f"Sending RSA response: {response}")
    messaging.send_message(conn, response)

    key_message = messaging.receive_message(conn)
    if key_message['opcode'] != 2 or key_message['type'] != "RSA":
        logging.error("Unexpected message from client")
        return

    encrypted_key: list = key_message['encrypted_key']
    logging.debug(f"Received Encrypted key: {encrypted_key}")
    aes_key = []
    for k in encrypted_key:
        aes_key.append(rsa.rsa_decrypt(k, private_key, p * q, True))
    aes_key = [b'\x00' if b == b'' else b for b in aes_key] # \x00 gets removed after JSON serialization
    logging.debug(f"Decrypted AES key: {aes_key}\nLength: {len(aes_key)}")
    
    response_message = "Server Response Message" # 서버의 메세지는 고정
    encrypted_response = sym.aes_encrypt(aes_key, response_message)
    logging.debug(f"Response message: {response_message}\nAES response: {encrypted_response}")
    response = messaging.create_message(2, "AES", encryption=encoding.byteencode(encrypted_response))
    logging.debug(f"Sending response: {response}")
    messaging.send_message(conn, response)

    aes_message = messaging.receive_message(conn)
    if aes_message['opcode'] != 2 or aes_message['type'] != "AES":
        logging.error("Unexpected message from client")
        return
    
    logging.debug(f"Received AES message: {aes_message}")
    decrypted_message = sym.aes_decrypt(aes_key, base64.b64decode(aes_message['encryption'].encode('ascii')))
    logging.info(f"Received decrypted message: {decrypted_message}")

def handle_protocol_3(conn):
    global args
    p, g = dh.generate_dh_params(2048)  # Use appropriate bit length
    if args.error == 1:
        p = 420
    elif args.error == 2:
        g = 1
    logging.debug(f"p: {p}, g: {g}")
    private_key, public_key = dh.generate_dh_keypair(p, g)
    # private_key = a, public_key = g^a mod p
    logging.debug(f"Private key: {private_key}\n Public key: {public_key}")
    
    response = messaging.create_message(1, "DH", 
                                        public=encoding.strencode(str(public_key)),
                                        parameter={"p": p, "g": g})
    logging.debug(f"Sending RSA response: {response}")
    messaging.send_message(conn, response)

    client_response = messaging.receive_message(conn)
    if client_response['opcode'] == 3:
        messaging.handle_error_message(client_response)
        return
    if client_response['opcode'] != 1 or client_response['type'] != "DH":
        logging.error("Unexpected message from client")
        return

    client_public = int(encoding.strdecode(client_response['public']))
    shared_secret = dh.compute_dh_shared_secret(private_key, client_public, p)
    aes_key = sym.generate_aes_key_from_dh(int.to_bytes(shared_secret, 2, 'big'))
    logging.debug(f"Shared secret: {shared_secret}\nByte representation: {int.to_bytes(shared_secret, 2, 'big')}\nAES key: {aes_key.hex()}")

    response_message = "Server DH Message" #서버의 메시지는 고정
    encrypted_response = sym.aes_encrypt(aes_key, response_message)
    response = messaging.create_message(2, "AES", encryption=encoding.byteencode(encrypted_response))
    messaging.send_message(conn, response)
    
    aes_message = messaging.receive_message(conn)
    if aes_message['opcode'] != 2 or aes_message['type'] != "AES":
        logging.error("Unexpected message from client")
        return
    
    logging.debug(f"Received AES message: {aes_message}")
    decrypted_message = sym.aes_decrypt(aes_key, base64.b64decode(aes_message['encryption'].encode('ascii')))
    logging.info(f"Received decrypted message: {decrypted_message}")

def handler(sock):
    try:
        while True:
            message = None
            try:
                message = messaging.receive_message(sock)
                if not message or message is None:
                    logging.info("Client disconnected")
                    break
                logging.info(f"Received message: {message}")
                if message['opcode'] == 0:
                    if message['type'] == "RSAKey":
                        handle_protocol_1(sock)
                    elif message['type'] == "RSA":
                        handle_protocol_2(sock)
                    elif message['type'] == "DH":
                        handle_protocol_3(sock)
            except json.JSONDecodeError as e:
                logging.error(f"JSON Decode Error: {e}, message: {message}")
                if message is None:
                    logging.info("Client disconnected")
                    break
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
    parser.add_argument("-e", "--error", metavar="<error scenario>", help="Protocol 4 Scenario (1/2)", type=int, default=0)
    args = parser.parse_args()
    return args

def main():
    global args
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()