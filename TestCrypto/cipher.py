"""
This module contains the methods and classes to produce the encryption of messages.
"""

import os

from Crypto.Cipher import AES
from secrets import token_bytes

from parameters import N, ROOT_DIR


# Size in bytes of each block supported by the cipher
BLOCK_SIZE = AES.block_size

# Size in bytes of the common Broadcast Key
BROADCAST_KEY_SIZE = N * BLOCK_SIZE

# File the common Broadcast Key is stored in
BROADCAST_KEY_FILE = "broadcast_key.pem"


def _read_broadcast_key():
    """Reads the common Broadcast Key from the proper file.
    :raises FileNotFoundError if the file doesn't exist
    :raises ValueError if the the length of the content of the file does not match BROADCAST_KEY_SIZE
    :return broadcast_key: the bytes sequence representing the common Broadcast Key"""
    with open(os.path.join(ROOT_DIR, BROADCAST_KEY_FILE), "rb") as f:
        broadcast_key = f.read()

    if not len(broadcast_key) == BROADCAST_KEY_SIZE:
        raise ValueError('Broadcast Key incorrent size')

    return broadcast_key


def _pad(msg):
    """Pads a message with empty bytes in order to fit it as a proper input for the cipher.
    For example, if the message is 41 bytes long and the block size is 16 bytes, it will be padded with 7 bytes"""
    if not len(msg) % BLOCK_SIZE == 0:
        return msg + b'\0' * (BLOCK_SIZE - len(msg) % BLOCK_SIZE)
    return msg


class Encryptor:
    """Class containing parameters and methods to produce the encryption of messages
    :param key: the bytes sequence representing the private encryption key
    :param broadcast_key: the bytes sequence representing the common Broadcast Key"""

    __slots__ = ['__key', '__broadcast_key']

    def __init__(self, key):
        """Class constructor
        :param key: the bytes sequence representing the private encryption key"""
        self.__key = key
        self.__broadcast_key = _read_broadcast_key()

    def encrypt(self, iv=None, msg=None):
        """Produces the encryption of a message.
        :param iv: (Optional) the bytes sequence representing the Initialization Vector of the block cipher;
            if not specified, a new IV is created as a random bytes sequence
        :param msg: (Optional) the bytes sequence representing the message to encrypt;
            if not specified, the common Broadcast Key will be encrypted
            (note that the protocol states to always encrypt the Broadcast Key, with different private keys)
        :returns the concatenation of the IV and the ciphertext corresponding to the plaintext"""
        if msg is None:
            msg = self.__broadcast_key
        msg = _pad(msg)

        if iv is None:
            iv = token_bytes(AES.block_size)

        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(msg)

        return iv + ciphertext


class Decryptor:
    """Class containing parameters and methods to produce the decryption of ciphertexts
    :param key: the bytes sequence representing the private decryption key
    :param broadcast_key: the bytes sequence representing the common Broadcast Key"""

    __slots__ = ['__key', '__broadcast_key']

    def __init__(self, key):
        """Class constructor
        :param key: the bytes sequence representing the private decryption key"""
        self.__key = key
        self.__broadcast_key = _read_broadcast_key()

    def decrypt(self, ciphertext):
        """Produces the decryption of a ciphertext.
        :param ciphertext the bytes sequence representing the ciphertext to decrypt
        :returns the plaintext corresponding to the ciphertext
        :raises ValueError if the plaintext does not correspond to the common Broadcast Key
            (as the protocol states to always encrypt the Broadcast Key, with different private keys"""
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])

        if not plaintext == self.__broadcast_key:
            raise ValueError('Ciphertext not valid')

        return plaintext.rstrip(b'\0')
