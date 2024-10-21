 #! PLEASE DO NOT USE NON-ASCII CHARACTERS (KOREAN) IN server.py AND client.py

import socket
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

def run_protocol_1(conn):
    # RSA Key Generation protocol
    request = messaging.create_message(0, "RSAKey")
    messaging.send_message(conn, request)
    
    response = messaging.receive_message(conn)
    logging.debug(f"Received response: {response}")
    
    if response['opcode'] == 3 and response['type'] == "error":
        logging.error(f"Error from server: {response['error']}")
        return
    
    if response['opcode'] != 0 or response['type'] != "RSAKey":
        logging.error("Unexpected response from server")
        return

    try:
        logging.debug(f"Private key: {response.get('private', 'Not found')}")
        logging.debug(f"Public key: {response.get('public', 'Not found')}")
        logging.debug(f"Parameters: {response.get('parameter', 'Not found')}")
        
        private_key = encoding.deserialize_key(response['private'])
        public_key = encoding.deserialize_key(response['public'])
        p = int(response['parameter']['p'])
        q = int(response['parameter']['q'])

        logging.info(f"Deserialized private key: {private_key}")
        logging.info(f"Deserialized public key: {public_key}")
        logging.debug(f"p: {p}")
        logging.debug(f"q: {q}")

        if rsa.verify_rsa_keypair(public_key, private_key, p, q):
            logging.info("RSA keypair verified successfully")
        else:
            logging.error("RSA keypair verification failed")
    except KeyError as e:
        logging.error(f"Missing key in response: {e}")
    except Exception as e:
        logging.error(f"Error processing RSA keypair: {e}")
        logging.exception("Exception details:")

def run_protocol_2(conn):
    
    request = messaging.create_message(0, "RSA")
    messaging.send_message(conn, request)
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 1 or response['type'] != "RSA":
        logging.error("Unexpected response from server")
        return

    public_key = encoding.deserialize_key(response['public'])
    n = int(response['parameter']['n'])

    aes_key = sym.generate_aes_key()
    encrypted_key = rsa.rsa_encrypt(aes_key, public_key)
    
    key_message = messaging.create_message(2, "RSA", encryption=base64.b64encode(encrypted_key).decode())
    messaging.send_message(conn, key_message)

    
    message = "Hello"
    encrypted_message = sym.aes_encrypt(aes_key, message.encode())
    aes_message = messaging.create_message(2, "AES", encryption=encrypted_message)
    messaging.send_message(conn, aes_message)

    response = messaging.receive_message(conn)
    if response['opcode'] != 2 or response['type'] != "AES":
        logging.error("Unexpected response from server")
        return

    decrypted_message = sym.aes_decrypt(aes_key, response['encryption'])
    logging.info(f"Received decrypted message: {decrypted_message.decode()}")

def run_protocol_3(conn):
    
    request = messaging.create_message(0, "DH")
    messaging.send_message(conn, request)
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 1 or response['type'] != "DH":
        logging.error("Unexpected response from server")
        return

    p = int(response['parameter']['p'])
    g = int(response['parameter']['g'])
    server_public = int(encoding.deserialize_key(response['public'])['key'])

    if not math.is_prime(p) or not dh.verify_dh_generator(g, p):
        error_msg = messaging.create_message(3, "error", error="Invalid DH parameters")
        messaging.send_message(conn, error_msg)
        logging.error("Invalid DH parameters received")
        return

    private_key, public_key = dh.generate_dh_keypair(p, g)
    dh_response = messaging.create_message(1, "DH", public=encoding.serialize_key({'key': public_key}))
    messaging.send_message(conn, dh_response)

    shared_secret = dh.compute_dh_shared_secret(private_key, server_public, p)
    aes_key = sym.generate_aes_key_from_dh(shared_secret)

    
    message = "Hello from client (DH)!"
    encrypted_message = sym.aes_encrypt(aes_key, message.encode())
    aes_message = messaging.create_message(2, "AES", encryption=encrypted_message)
    messaging.send_message(conn, aes_message)

    response = messaging.receive_message(conn)
    if response['opcode'] != 2 or response['type'] != "AES":
        logging.error("Unexpected response from server")
        return

    decrypted_message = sym.aes_decrypt(aes_key, response['encryption'])
    logging.info(f"Received decrypted message: {decrypted_message.decode()}")

def run_protocol_4_1(conn):
    
    request = messaging.create_message(0, "DH")
    messaging.send_message(conn, request)
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 1 or response['type'] != "DH":
        logging.error("Unexpected response from server")
        return

    p = int(response['parameter']['p'])
    g = int(response['parameter']['g'])

    if not math.is_prime(p):
        error_msg = messaging.create_message(3, "error", error="incorrect prime number")
        messaging.send_message(conn, error_msg)
        logging.error("Non-prime number received in DH parameters")
    else:
        logging.info("Received a prime number, which was not expected for this error case")

def run_protocol_4_2(conn):
    
    request = messaging.create_message(0, "DH")
    messaging.send_message(conn, request)
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 1 or response['type'] != "DH":
        logging.error("Unexpected response from server")
        return

    p = int(response['parameter']['p'])
    g = int(response['parameter']['g'])

    if not dh.verify_dh_generator(g, p):
        error_msg = messaging.create_message(3, "error", error="incorrect generator")
        messaging.send_message(conn, error_msg)
        logging.error("Incorrect generator received in DH parameters")
    else:
        logging.info("Received a correct generator, which was not expected for this error case")

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Client is connected to {}:{}".format(addr, port))

    try:
        while True:
            print("\nChoose an action:")
            print("1: RSA Key Generation")
            print("2: RSA Encryption and AES")
            print("3: Diffie-Hellman Key Exchange and AES")
            print("4_1: DH with non-prime error")
            print("4_2: DH with incorrect generator error")
            print("5: Exit")

            choice = input("Enter your choice (1-4_2, or 5 to exit): ")

            try:
                if choice == '1':
                    run_protocol_1(conn)
                elif choice == '2':
                    run_protocol_2(conn)
                elif choice == '3':
                    run_protocol_3(conn)
                elif choice == '4_1':
                    run_protocol_4_1(conn)
                elif choice == '4_2':
                    run_protocol_4_2(conn)
                elif choice == '5':
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")
            except json.JSONDecodeError as e:
                logging.error(f"JSON Decode Error: {e}")
                print(f"Error in JSON parsing. Details: {e}")
            except Exception as e:
                logging.error(f"Error in protocol execution: {e}")
                print(f"An error occurred: {e}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        conn.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
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