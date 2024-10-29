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
        
        private_key = int(response['private'])
        public_key = int(response['public'])
        p = int(response['parameter']['p'])
        q = int(response['parameter']['q'])

        logging.info(f"Private key (d): {private_key}")
        logging.info(f"Public key (e): {public_key}")
        logging.info(f"p: {p}")
        logging.info(f"q: {q}")

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
    logging.debug(f"Received response: {response}") if response else logging.error("No response received")
    if response['opcode'] != 1 or response['type'] != "RSA":
        logging.error("Unexpected response from server")
        return

    public_key = int(response['public'])
    n = int(response['parameter']['n'])

    aes_key = sym.generate_aes_key(as_list=True)
    logging.debug(f"AES key: {aes_key}\nLength: {len(aes_key)}")
    encrypted_key = []
    for k in aes_key:
        encrypted_key.append(rsa.rsa_encrypt(k, public_key, n))
    logging.debug(f"Encrypted key: {encrypted_key}")
    
    key_message = messaging.create_message(2, "RSA", encrypted_key=encrypted_key)
    logging.debug(f"Sending AES key message: {key_message}")
    messaging.send_message(conn, key_message)
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 2 or response['type'] != "AES":
        logging.error("Unexpected response from server")
        return

    decrypted_message: str = sym.aes_decrypt(aes_key, base64.b64decode(response['encryption'].encode('ascii')))
    logging.info(f"Received decrypted message: {decrypted_message}")
    
    message = input("Enter message: ")
    encrypted_message: bytes = sym.aes_encrypt(aes_key, message)
    aes_message = messaging.create_message(2, "AES", encryption=encoding.byteencode(encrypted_message))
    logging.debug(f"Sending AES message: {aes_message}")
    messaging.send_message(conn, aes_message)

def run_protocol_3(conn):
    request = messaging.create_message(0, "DH")
    messaging.send_message(conn, request)
    logging.debug(f"Sent DH request: {request}")
    
    response = messaging.receive_message(conn)
    if response['opcode'] != 1 or response['type'] != "DH":
        logging.error("Unexpected response from server")
        return

    p = int(response['parameter']['p'])
    g = int(response['parameter']['g'])
    server_public = int(encoding.strdecode(response['public']))
    logging.debug(f"Received DH parameters: p: {p}, g: {g}")

    if not math.is_prime(p):
        error_msg = messaging.create_message(3, "error", error="Invalid DH parameters: p is not prime")
        messaging.send_message(conn, error_msg)
        logging.error(f"Invalid DH parameters received / non-prime p({p})")
        return
    if not dh.verify_dh_generator(g, p):
        error_msg = messaging.create_message(3, "error", error="Invalid DH parameters: g is not a generator")
        messaging.send_message(conn, error_msg)
        logging.error(f"Invalid DH parameters received / non-generator g({g})")
        return

    private_key, public_key = dh.generate_dh_keypair(p, g)
    # private_key = b, public_key = g^b mod p
    dh_response = messaging.create_message(1, "DH", public=encoding.strencode(str(public_key)), parameter={"p": p, "g": g})
    logging.debug(f"Sending DH response: {dh_response}")
    messaging.send_message(conn, dh_response)

    shared_secret = dh.compute_dh_shared_secret(private_key, server_public, p)
    aes_key = sym.generate_aes_key_from_dh(int.to_bytes(shared_secret, 2, 'big'))
    logging.debug(f"Shared Secret: {shared_secret}\nByte Representation: {int.to_bytes(shared_secret, 2, 'big')}\nAES key: {aes_key.hex()}\nLength: {len(aes_key)}")

    response = messaging.receive_message(conn)
    if response['opcode'] != 2 or response['type'] != "AES":
        logging.error("Unexpected response from server")
        return

    decrypted_message = sym.aes_decrypt(aes_key, base64.b64decode(response['encryption'].encode('ascii')))
    logging.info(f"Received decrypted message: {decrypted_message}")
    
    message = input("Enter message: ")
    encrypted_message: bytes = sym.aes_encrypt(aes_key, message)
    aes_message = messaging.create_message(2, "AES", encryption=encoding.byteencode(encrypted_message))
    logging.debug(f"Sending AES message: {aes_message}")
    messaging.send_message(conn, aes_message)

def run(addr, port, autorun):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Client is connected to {}:{}".format(addr, port))
        
    if autorun:
        logging.debug("Starting protocol 1: RSA Key Generation")
        run_protocol_1(conn) # Autorun
        
    try:
        while True:
            print("\nChoose an action:")
            print("1: RSA Key Generation")
            print("2: RSA Encryption and AES")
            print("3: Diffie-Hellman Key Exchange and AES")
            print("4_1: DH with non-prime error")
            print("4_2: DH with incorrect generator error")
            print("5: Exit")

            choice = input("Enter your choice (1-3, or 5 to exit): ")

            try:
                if choice == '1':
                    run_protocol_1(conn)
                elif choice == '2':
                    run_protocol_2(conn)
                elif choice == '3':
                    run_protocol_3(conn)
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
    parser.add_argument("-r", "--run", metavar="<autorun protocol 1?>", help="Autorun Protocol 1 upon script start", type=bool, default=False)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    autorun = args.run
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, autorun)
    
if __name__ == "__main__":
    main()