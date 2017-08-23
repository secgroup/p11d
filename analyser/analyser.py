#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import logging
import argparse
import binascii
from os import listdir
from os.path import isfile, join
from Crypto.Cipher import DES

# global variables

FKS = set()
H = set()


# function definitions

def add_sensitive_handler(session, key):
    global H, FKS

    # check if this is a sensitive or a non-extractalbe key
    if key['sensitive'] == '01' or key['extractable'] == '00':
        H.add((session, key['handle']))
        for func, res in key['fingerprint'].items():
            fprint = tuple(binascii.unhexlify(d) for d in res)
            FKS.add((func,) + fprint)


def log_analysis(traces):
    logging.info('Computing H and FSK')
    for session, trace in traces.items():
        for action in trace:
            try:
                act = json.loads(action)
            except json.decoder.JSONDecodeError:
                continue
            if act[0] == 'C_Login':
                for key in act[1]:
                    add_sensitive_handler(session, key)
            elif act[0] == 'C_GenerateKey':
                # keys created with C_CreateObject cannot be considered secure because the
                # value is provided in clear
                add_sensitive_handler(session, key)

    logging.info('Searching for insecure Wrap and Decrypt operations')
    for session, trace in traces.items():
        for action in trace:
            try:
                act = json.loads(action)
            except json.decoder.JSONDecodeError:
                continue
            if act[0] == 'C_WrapKey':
                h_wrapping_key, h_wrapped_key = act[1]
                if (session, h_wrapping_key) not in H and (session, h_wrapped_key) in H:
                    logging.critical(
                        ('Attack detected in {}! The sensitive key h{} has been '
                         'wrapped with the insecure key h{}').format(
                            session, h_wrapped_key, h_wrapping_key))
                    sys.exit(1)
            elif act[0] == 'C_Decrypt':
                h_dec_key = act[1][0]
                if (session, h_dec_key) in H:
                    dec_key = binascii.unhexlify(act[2])
                    for fp_oper, fp_param, fp_ret in FKS:
                        ret = None
                        if fp_oper == 'encrypt':
                            # encrypt fp_param with dec_key and see if the result matches fp_ret
                            cipher = DES.new(dec_key, DES.MODE_ECB)
                            ret = cipher.encrypt(fp_param)
                        elif fp_oper == 'decrypt':
                            # decrypt fp_param with dec_key and see if the result matches fp_ret
                            cipher = DES.new(dec_key, DES.MODE_ECB)
                            ret = cipher.decrypt(fp_param)
                        elif fp_oper == 'wrap':
                            # encrypt dec_key with dec_key and see if the result matched fp_ret
                            cipher = DES.new(dec_key, DES.MODE_ECB)
                            ret = cipher.encrypt(dec_key)

                        if fp_ret == ret:
                            logging.critical(
                                ('Attack detected in {}! The plaintext value of a sensitive '
                                 'key has been leaked after decryption with key {}').format(
                                    session, h_dec_key))
                            sys.exit(1)


def main():
    # command line argument parser definition
    parser = argparse.ArgumentParser(description='Log Analyser')
    parser.add_argument('-i', dest='logdir', default='/tmp/apilogger',
                        help='Logging directory to analyse, default /tmp/apilogger')
    parser.add_argument('-v', dest='verbose', action='store_true', 
                        default=False, help='Set logging level to debug')
    args = parser.parse_args()
    # variables initialization
    log_dir = args.logdir
    # logger initialization
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p', level=log_level)
    traces = dict()
    for f in listdir(log_dir):
        log_file = join(log_dir, f)
        if isfile(log_file):
            with open(log_file) as fd:
                traces[log_file] = fd.read().split('\n')
                logging.debug('Read log file {}'.format(log_file))
    log_analysis(traces)


if __name__ == '__main__':
    main()
