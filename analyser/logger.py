#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import signal
import socket
import logging
import argparse
from copy import copy
from socket import SHUT_RDWR

sock = None
sock_file = None
log_dir = None

# function definitions

def init_logdir():
    """Creates the logging directory if it doesn't exist."""

    try:
        os.mkdir(log_dir, mode=0o700)
        logging.info('Created directory {}'.format(log_dir))
    except FileExistsError as e:
        pass


def init_socket():
    """Initializes the socket and binds the server to the provided file."""

    global sock

    if os.path.exists(sock_file):
        os.remove(sock_file)
    logging.info('Opening socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(sock_file)
    sock.listen(5)
    logging.info('Listening')


def kill_socket():
    """Terminates the server and removes the socket file."""

    logging.info('Sutting down')
    sock.close()
    os.remove(sock_file)


def signal_handler(signal, frame):
    """Handles explicit interruptions."""

    logging.exception('Received Ctrl-C, terminating...')
    if sock:
        kill_socket()
    sys.exit(1)


def to_logfile(fd, data):
    if data is not None:
        # remove trailing commas to make the json parser happy
        sanitized_data = data.decode().replace(', }', '}').replace(', ]', ']')
        json_data = json.loads(sanitized_data)
        fd.write('{}\n'.format(json.dumps(json_data)))


def recv_until(s, end=b'\n'):
    data = b''
    while not data.endswith(end):
        data += s.recv(1)

    return data


def listen():
    """Listens to new connections."""

    while True:
        conn, addr = sock.accept()
        logging.info('Accepted connection')
        log_file = os.path.join(log_dir, 'session-{}.log'.format(time.strftime('%Y:%m:%d-%H:%M:%S')))
        with open(log_file, 'a') as f:
            while True:
                data = recv_until(conn)
                if not data or data.startswith(b'END'):
                    logging.debug('Bye...')
                    break
                else:
                    to_logfile(f, data)
                    logging.debug('Received {}'.format(data))


def main():
    global soc, sock_file, log_dir

    # command line argument parser definition
    parser = argparse.ArgumentParser(description='API logger')
    parser.add_argument('-s', dest='sockfile', default='/tmp/apilogger.sock',
        help='Pathname of the Unix socket to communicate with the wrapped library')
    parser.add_argument('-o', dest='logdir', default='/tmp/apilogger',
        help='Logging directory, default /tmp/apilogger')
    parser.add_argument('-v', dest='verbose', action='store_true', 
        default=False, help='Set logging level to debug')
    args = parser.parse_args()
    # global variables initialization
    sock_file = args.sockfile
    log_dir = args.logdir
    # logger initialization
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p', level=log_level)
    # handle ctrl-c
    signal.signal(signal.SIGINT, signal_handler)
    # server initialization
    init_socket()
    init_logdir()
    # listen for new connection
    listen()
    # server termination
    kill_socket()

if __name__ == '__main__':
    main()
