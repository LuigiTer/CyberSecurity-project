#! /bin/python3

import sys
sys.path.append('../')


import socket
import ssl

from definitions import EPHID_SIZE, SIGNATURE_SIZE
from key_generator import PUBLIC_KEY_SIZE, PublicSK
from signatures import Verifier


MESSAGE_SIZE = PUBLIC_KEY_SIZE + EPHID_SIZE + SIGNATURE_SIZE

SERVER_BACKEND_CERT_PATH = "../intermediateCA/certs/intermediateCA-rootCA-chain.cert.pem"
SERVER_BACKEND_KEY_PATH = "../intermediateCA/private/intermediateCAkey.pem"

HOST = '127.0.0.1'
PORT = 8443


def verify(sk, ephid, tag):
    """
    This function verifies that the signature tag is valid and corresponds to the signature of the EphID generated using
    the private key of an infected person. The verification process needs the public key.
    Since the signature algorithm uses elliptic curves, we only need two
    paramters, x and y, to reconstruct the public key of the infected person.
    The type of curve is defined by the protocol.
    :param sk: public key used to verify
    :param ephid: the original ephid transmitted by the non infected person
    :param tag: the signature of the ephid to be verified
    :return True if the signature is valid or not
    """
    pk = PublicSK.construct_public_key(sk)
    verifier = Verifier(pk)
    signature_valid = verifier.verify(ephid, tag)
    return signature_valid


def split_message(data):
    """
    Split the message in different parts, as defined by the protocol
    :param data: the message to split
    :return x, y, ephid, tag: the 4 parts of the message, as defined by the protocol
    """
    sk = data[:PUBLIC_KEY_SIZE]
    ephid = data[PUBLIC_KEY_SIZE: PUBLIC_KEY_SIZE + EPHID_SIZE]
    tag = data[-SIGNATURE_SIZE:]
    return sk, ephid, tag


def main():
    # opening a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    # accept the connection from the client
    client, fromaddr = server_socket.accept()
    secure_sock = ssl.wrap_socket(client, server_side=True, certfile=SERVER_BACKEND_CERT_PATH,
                                  keyfile=SERVER_BACKEND_KEY_PATH)

    # prints the name of the connected peer and the cipher suite.
    print(repr(secure_sock.getpeername()))
    print(secure_sock.cipher())

    try:
        secure_sock.write(b"Welcome to the serverDP3T! Who has violated the quarantine?")
        # reading the data from the client and checking that it is correct
        data = secure_sock.read(MESSAGE_SIZE)
        if len(data) != MESSAGE_SIZE:
            raise IndexError

        # splitting the message in different part
        sk, ephid, tag = split_message(data)

        if verify(sk, ephid, tag):
            secure_sock.write(b'Thanks for your help :) the subject has violated the quarantine!')
        # here the autority will be notified of the violation of the quatantine by the person who has
        # that public key.
        else:
            secure_sock.write(b'Thanks for your help :( but you are trying to scam the system...')
    # someone is trying to forge the signature. ban him.
    except IndexError as e:
        secure_sock.write(b'The message is not valid.')
    finally:
        secure_sock.close()
        server_socket.close()


if __name__ == '__main__':
    while True:
        main()
