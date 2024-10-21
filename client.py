import socket
import argparse
import logging

from _utils import rsa_utils as rsa
from _utils import dh_utils as dh
from _utils import symmetric as sym
from _utils import math_utils as math
from _utils import encoding as encoding
from _utils import message_utils as messaging

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Client is connected to {}:{}".format(addr, port))

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