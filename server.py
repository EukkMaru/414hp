import socket
import threading
import argparse
import logging

from _utils import rsa_utils as rsa
from _utils import dh_utils as dh
from _utils import symmetric as sym
from _utils import math_utils as math
from _utils import encoding as encoding
from _utils import message_utils as messaging

def handler(sock):
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