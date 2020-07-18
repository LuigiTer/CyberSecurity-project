""""
This module contains the script to run everytime the user wants to check the recent contacts with infected people.
"""

# ! /bin/python3

import sys

sys.path.append('../')

import os
from datetime import datetime

from secrets import token_bytes

from cipher import Encryptor
from crhf import H
from definitions import PACKET_SIZE, IV_SIZE, EPHID_SIZE, SIGNATURE_SIZE
from key_generator import PUBLIC_KEY_SIZE, PublicSK, SK_SIZE, Key
from parameters import N
from receiver.client import send_data_to_server
from receiver.rec_definitions import (PUBLIC_KEY_INFECTED_FILE, SK_INFECTED_FILE, LAST_SK_INFECTED_UPDATE_FILE,
                                      EPHID_AND_SIGNATURE_FILE)
from signatures import Verifier

from utils import split_sequence, split_in_chunks


def read_keys():
    """Gets the Public keys and the SKs of the infected users, reading them from the proper files.
    Then, all stored SKs will be updated depending on the date of the last update and the current date.
    If the file containing the date of the last update of the SKs of the infected users doens't exist,
    a new one will be created, containing the current date.
    If the file containing the public keys of the infected users doesn't exist,
    it means that there are no infected users in the system, thus the algorithm ends.
    :raises ValueError if:
        the content of the file containing the public keys of the infected users is not compatible
            with the size of the public key
        the content of the file containing the SKs of the infected users is not compatible with the size of SK in bytes
        the number of public keys and SKs read are different
    :return public_key_list: a list of the public keys of all infected users
    :return sk_list: a list of the properly updated SKs of all infected users"""
    try:
        with open(LAST_SK_INFECTED_UPDATE_FILE, "r") as f:
            last_update = datetime.strptime(f.read(), Key.LAST_UPDATE_DATE_FORMAT)
    except FileNotFoundError:
        with open(LAST_SK_INFECTED_UPDATE_FILE, "w") as f:
            last_update = datetime.now()
            f.write(last_update.strftime(Key.LAST_UPDATE_DATE_FORMAT))

    try:
        with open(PUBLIC_KEY_INFECTED_FILE, "rb") as f:
            public_key_list = f.read()
        if not len(public_key_list) % PUBLIC_KEY_SIZE == 0:
            raise ValueError(f"File {PUBLIC_KEY_INFECTED_FILE} does not contain proper public keys")
        public_key_list = split_in_chunks(public_key_list, PUBLIC_KEY_SIZE)
    except FileNotFoundError:
        print('No Public Keys in the database.')
        return [], []

    try:
        with open(SK_INFECTED_FILE, "rb") as f:
            sk = f.read()
        if not len(sk) % SK_SIZE == 0:
            raise ValueError(f"File {SK_INFECTED_FILE} does not contain proper SKs")
        sk_list = split_in_chunks(sk, SK_SIZE)
    except FileNotFoundError:
        raise ValueError(f"File {SK_INFECTED_FILE} doesn't exist!")

    if not len(public_key_list) == len(sk_list):
        raise ValueError(f'Files {PUBLIC_KEY_INFECTED_FILE} and {SK_INFECTED_FILE} contain different number of keys')

    days = (datetime.now() - last_update).days

    if not days > 0:
        return public_key_list, sk_list

    for sk in sk_list:
        for _ in range(days):
            sk = H(sk)

        with open(os.path.join(SK_INFECTED_FILE), "wb") as f:
            f.write(sk)

    with open(os.path.join(LAST_SK_INFECTED_UPDATE_FILE), "w") as f:
        f.write(datetime.now().strftime(Key.LAST_UPDATE_DATE_FORMAT))

    return public_key_list, sk_list


def read_packets():
    """Gets the BLE packets received by the other users, reading them from the proper file,
    and splits them into IV, EphID and signature.
    If the file containing the packets k doesn't exist,
    it means that the user has not received any packet, thus the algorithm ends.
    :raises ValueError if the content of the file containing the packets is not compatible with the packet size
    :return iv_list: a list of the IVS to check if one of the infected users can generate one of the received EphIDs
    :return ephid_list: a list of the received EphIDs
    :return tag_list: a list of the received signatures"""
    try:
        with open(EPHID_AND_SIGNATURE_FILE, "rb") as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print('No EphIDs received yet.')
        return [], [], []

    if not len(ciphertext) % PACKET_SIZE == 0:
        raise ValueError('ciphertext size not valid')

    packets = split_in_chunks(ciphertext, PACKET_SIZE)

    iv_list = []
    ephid_list = []
    tag_list = []

    for packet in packets:
        iv = packet[:IV_SIZE]
        ephid = packet[IV_SIZE:IV_SIZE + EPHID_SIZE]
        tag = packet[-SIGNATURE_SIZE:]
        iv_list.append(iv)
        ephid_list.append(ephid)
        tag_list.append(tag)

    return iv_list, ephid_list, tag_list


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
    """
    pk = PublicSK.construct_public_key(sk)
    verifier = Verifier(pk)
    signature_valid = verifier.verify(ephid, tag)
    return signature_valid


def main(is_adv):
    packets = (iv_list, ephid_list, tag_list) = read_packets()  # Read all the packets received
    print('#EphIDs:', len(packets[1]))

    keys = (public_key_list, sk_list) = read_keys()  # Read all the public keys of infected users received
    print('#SK:', len(keys[1]))

    for (public_key, sk) in zip(*keys):
        encryptor = Encryptor(sk)
        for (iv, ephid, tag) in zip(*packets):
            ciphertext = encryptor.encrypt(iv=iv)  # Generate the EphIDs corresponding to each SK
            ephids = ciphertext[IV_SIZE:]
            blocks = split_sequence(ephids, N)
            advtag = tag[:-1] + token_bytes(1)  # The tag computed by an adversary
            # Check if one of the received EphIDs can be generated by SK
            if ephid not in blocks:
                continue
            else:
                # the tag to send is the received one itself if the user is honest
                tag_to_send = advtag if is_adv else tag
                print(ephid.hex())

                retval = verify(public_key, ephid, tag_to_send)  # True if the tag is honest, False otherwise
                print(retval)

                data = public_key + ephid + tag_to_send  # Send <pk,ephid,tag> to server
                send_data_to_server(data)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # The first argument is a simulation variable
        # Run python script_receiver.py 1 on the shell if you want to simulate an adversary-like behavior
        # Run python script_receiver.py 0 on the shell if you want to simulate a honest-user-like behavior
        main(bool(int(sys.argv[1])))
    else:
        raise SystemError('Invalid launch command.')
