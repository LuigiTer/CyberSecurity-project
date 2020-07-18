""""
This module contains the script to run everytime the user wants to broadcast EphIDs via BLE.
"""

#! /bin/python3

import sys
sys.path.append('../')

import os
from datetime import datetime

from parameters import N, L, SK_SIZE
from definitions import IV_SIZE, SIGNATURE_SIZE, PACKET_SIZE
from sender.sen_definitions import CIPHERTEXT_FILE, LAST_CIPHERTEXT_UPDATE_FILE
from receiver.rec_definitions import (EPHID_AND_SIGNATURE_FILE, RECEIVER_DIR, PUBLIC_KEY_INFECTED_FILE,
                                      SK_INFECTED_FILE)

from key_generator import PublicSK, PrivateSK
from cipher import Encryptor
from signatures import Signer

from utils import split_sequence, get_current_minutes, append_if_absent


def generateSK(is_infected):
    """Return the holder of the user's SK, used to encrypt the common Broadcast Key to produce EphIDs.
    If the user is infected, then SK will contain a representation of the user's public key.
    If the user is NOT infected, then SK will contain a random bytes sequence.
    :param is_infected: a boolean variable; it is True if the user is infected, False otherwise
    :returns a {Public,Private}SK object depending on where the user is infected or not,
        storing the information about the user's SK"""
    if is_infected:
        sk = PublicSK()
    else:
        sk = PrivateSK()
    return sk


def get_ciphertext_from_file(sk):
    """Reads the current ciphertext from the corrisponding file,
    containing the output of the cipher, encrypting the common Broadcast Key.
    It changes everyday, and stays the same during the whole day.
    Returns the content of the file the ciphertext is stored in; if it has not been created yet, this means that
    the user is using the system for the first time,
    thus a new file will be created and the first ciphertext will be stored in it.
    :param sk: a {Public,Private}SK object storing the information about the user's SK, used for encryption
    :return ciphertext: the bytes sequence representing the read ciphertext"""
    path = os.path.join(sk.directory(), CIPHERTEXT_FILE)
    try:
        with open(path, "rb") as f:
            ciphertext = f.read()
    except FileNotFoundError:
        with open(path, "wb") as f:
            encryptor = Encryptor(sk.get())
            ciphertext = encryptor.encrypt()
            f.write(ciphertext)
    return ciphertext

def get_last_ciphertext_update_from_file(sk):
    """Reads the last time the ciphertext has been updated.
    Returns the content of the file the date of the last update is stored in;
    if it has not been created yet, this means that the user is using the system for the first time,
    thus a new file will be created and the current date will be stored in it.
    :param sk: a {Public,Private}SK object storing the information about the user's SK,
        used for deciding where the file is supposed to be stored
    :return last_update: a datetime object representing the last time the ciphertext has been updated"""
    path = os.path.join(sk.directory(), LAST_CIPHERTEXT_UPDATE_FILE)
    try:
        with open(path, "r") as f:
            last_update = datetime.strptime(f.read(), sk.LAST_UPDATE_DATE_FORMAT)
    except FileNotFoundError:
        with open(path, "w") as f:
            last_update = datetime.now()
            f.write(last_update.strftime(sk.LAST_UPDATE_DATE_FORMAT))
    return last_update

def update_ciphertext(last_update, sk):
    """Updates the ciphertext, depending on the last time it has been updated, and the corresponding file too.
    If the date of the last update is the current date, no update at all will be performed;
    otherwise, the common Broadcast Key will be encrypted using the current SK.
    :param last_update: a datetime object representing the last time the ciphertext has been updated
    :param sk: a {Public,Private}SK object storing the information about the user's SK,
        used for encryption and also for deciding where the file is supposed to be stored
    :return ciphertext: the bytes sequence representing the updated ciphertext"""
    path = os.path.join(sk.directory(), CIPHERTEXT_FILE)
    days = (datetime.now() - last_update).days

    if not days > 0:
        return open(path, "rb").read()

    with open(path, "wb") as f:
        encryptor = Encryptor(sk.get())
        ciphertext = encryptor.encrypt()
        f.write(ciphertext)

    with open(os.path.join(sk.directory(), LAST_CIPHERTEXT_UPDATE_FILE), "w") as f:
        f.write(datetime.now().strftime(sk.LAST_UPDATE_DATE_FORMAT))

    return ciphertext

def encrypt(sk):
    """Returns the encryption of the common Broadcast Key.
    :param sk: a {Public,Private}SK object storing the information about the user's SK, used for encryption
    :return ciphertext: the bytes sequence representing the current ciphertext (IV + N EphIDs)"""
    ciphertext = get_ciphertext_from_file(sk)

    last_update = get_last_ciphertext_update_from_file(sk)

    ciphertext = update_ciphertext(last_update, sk)

    return ciphertext


def getEphID(sk):
    """Returns the current EphID to broadcast. It changes every L minutes.
    For example, the first EphID will be broadcasted for the first L minutes of the day;
    the second EphID will be broadcasted for the second L minutes of the day, and so on.
    :param sk: a {Public,Private}SK object storing the information about the user's SK,
        used for deciding where the file containing the EphIDs is supposed to be stored"""
    with open(os.path.join(sk.directory(), CIPHERTEXT_FILE), "rb") as f:
        ciphertext = f.read()
    ephids = ciphertext[IV_SIZE:]
    ephid_list = split_sequence(ephids, N)
    if not len(ephid_list) == N:
        raise ValueError('Not enough EphIDs in ciphertext')
    minutes_from_midnight = get_current_minutes()
    ephid = ephid_list[minutes_from_midnight // L]
    return ephid


def sign(sk, ephid):
    """Returns the signature of an EphID.
    :param sk: a PublicSK object storing the information about the user's SK, containing the private signature key too.
    :param ephid: the EphID to sign
    :return signature: the signature for :param ephid"""
    key = PublicSK.get_private_key(sk)
    signer = Signer(key)
    signature = signer.sign(ephid)
    return signature


def main(is_infected):
    """The main script to run.
    :param is_infected: a boolean variable; it is True if the user is infected, False otherwise"""
    sk = generateSK(is_infected)  	# Get the current SK

    ciphertext = encrypt(sk)	  	# Get the current ciphertext

    ephid = getEphID(sk)			# Get the current EphID

    if is_infected:
        signature = sign(sk, ephid)  			# The signature is computed as per the used signature scheme
    else:
        signature = b'\0' * SIGNATURE_SIZE		# The signature is computed as a sequence of SIGNATURE_SIZE empty bytes

    # THIS IS A SIMULATION. IV + EPHID + SIGNATURE WILL BE SENT IN BROADCAST VIA BLE IN REAL-WORLD APPLICATION
    iv = ciphertext[:IV_SIZE]			# IV is the first part of the ciphertext
    packet = iv + ephid + signature		# The packet is made of <iv, ephid, signature>
    # The packet is sent to the receiver (in the simulation, it is saved in the proper file)
    append_if_absent(packet, PACKET_SIZE, os.path.join(RECEIVER_DIR, EPHID_AND_SIGNATURE_FILE))

    # THIS IS A SIMULATION.
    # THE PUBLIC KEYS AND THE SK OF INFECTED USERS WILL BE SENT TO OTHER USERS BY THE SERVER IN REAL-WORLD APPLICATION
    if is_infected:
        # The public key is sent to the receiver (in the simulation, it is saved in the proper file)
        sk.export_public_key(os.path.join(RECEIVER_DIR, PUBLIC_KEY_INFECTED_FILE))
        # The receiver computes the SK from the public key (in the simulation, it is saved in the proper file)
        append_if_absent(sk.get(), SK_SIZE, os.path.join(RECEIVER_DIR, SK_INFECTED_FILE))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        # The first argument is a simulation variable
        # Run python script_sender.py 1 on the shell if you want to simulate an infected-user-like behavior
        # Run python script_sender.py 0 on the shell if you want to simulate a non-infected-user-like behavior
        main(bool(int(sys.argv[1])))
    else:
        raise SystemError('Invalid launch command.')
