"""
This module contains the methods and classes to produce signatures of messages.
It follows the Digital Signature Standard (DSS) to sign messages.
It uses the Elliptic Curve Encyption (ECC) to produce key pairs valid for signing messages.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
"""


from Crypto.Hash import SHA256
from Crypto.Signature import DSS

from definitions import STANDARD


class Signer:
    """Class containing parameters and methods to produce the signatures of messages
    :param key: the EccKey object holding the private signature key"""

    __slots__ = ['__key']

    def __init__(self, key):
        """Class constructor
        :param key: the EccKey object holding the private signature key"""
        self.__key = key

    def sign(self, msg):
        """Produces the signature for a message.
        :param msg: the message to sign
        :return signature: the signature for :param msg"""
        h = SHA256.new(msg)
        signer = DSS.new(self.__key, STANDARD)
        signature = signer.sign(h)
        return signature


class Verifier:
    """Class containing parameters and methods to verify the signatures of messages
    :param key: the EccKey object holding the public signature key"""

    __slots__ = ['__key']

    def __init__(self, key):
        """Class constructor
        :param key: the EccKey object holding the public signature key"""
        self.__key = key

    def verify(self, msg, tag):
        """Produces if a signature for a message is valid.
        :param msg: the signed message
        :param tag: the signature to verify
        :returns True if the signature is valid, False otherwise"""
        h = SHA256.new(msg)
        verifier = DSS.new(self.__key, STANDARD)
        try:
            verifier.verify(h, tag)
            return True
        except (ValueError, TypeError):
            return False
