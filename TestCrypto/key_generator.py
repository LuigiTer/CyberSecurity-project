"""
This module contains the methods and classes to generate both private and public SKs.
""" 


from abc import ABC
from datetime import datetime
import os

from Crypto.PublicKey import ECC
from secrets import token_bytes

from crhf import H
from definitions import STANDARD_CURVE
from parameters import SK_SIZE

from utils import append_if_absent


# Size in bytes of the public key. It depends on the Signature Algorithm (in this case, ECC)
PUBLIC_KEY_SIZE = 2 * SK_SIZE


class Key(ABC):
    """An Abstract Base Class representing an SK
    :param sk: the bytes sequence representing the SK held by the class"""

    # Directory in which the files containing the SKs will be stored
    DIRECTORY = "."

    # File the SK is stored in
    SK_FILE = "sk.pem"

    # File the date of the last update of the SK is stored in
    LAST_SK_UPDATE_FILE = "last_sk_update.txt"

    # Format the last update date is saved with (e.g. 2020-06-01)
    LAST_UPDATE_DATE_FORMAT = '%Y-%m-%d'

    __slots__ = ['__sk']

    def __init__(self):
        """Class constructor.
        Stores in :param sk the SK of the current day"""
        self.__sk = self._get_current_sk()

    def _get_sk_from_file(self):
        """Reads the SK from the corresponding file.
        If the file doesn't exist, a new one will be created, containing a new SK"""
        pass

    def get_last_sk_update_from_file(self):
        """Reads the date of the last update of the SK from the corresponding file.
        If the file doens't exist, a new one will be created, containing the current date
        :return last_update: a datetime object"""
        path = os.path.join(self.directory(), self.LAST_SK_UPDATE_FILE)
        try:
            with open(path, "r") as f:
                last_update = datetime.strptime(f.read(), self.LAST_UPDATE_DATE_FORMAT)
        except FileNotFoundError:
            with open(path, "w") as f:
                last_update = datetime.now()
                f.write(last_update.strftime(self.LAST_UPDATE_DATE_FORMAT))
        return last_update

    def _update_sk(self, last_update, sk):
        """Updates the SK depending on the last time it has been updated and the current date.
        The update criterion is the digest H of the previous SK.
        If the date of the last update is the current date, no update at all will be performed.
        The files containing the current SK and the date of the last update (i.e., current date)
        will be properly updated too.
        For example, if the last update date is yesterday, then SK = H(SK)
        If the last update date is the day before yesterday, then SK = H(H(SK))
        :param last_update: a datetime object representing the last time the SK has been updated
        :param sk: the SK to update
        :return sk: the updated SK"""
        days = (datetime.now() - last_update).days

        if not days > 0:
            return sk

        for _ in range(days):
            sk = H(sk)

        with open(os.path.join(self.directory(), self.SK_FILE), "wb") as f:
            f.write(sk)

        with open(os.path.join(self.directory(), self.LAST_SK_UPDATE_FILE), "w") as f:
            f.write(datetime.now().strftime(self.LAST_UPDATE_DATE_FORMAT))

        return sk

    def _get_current_sk(self):
        """Generates the proper SK for the current day.
        :return sk: the SK to use the current day"""
        sk = self._get_sk_from_file()

        last_update = self.get_last_sk_update_from_file()

        return self._update_sk(last_update, sk)

    def get(self):
        """:return sk: the bytes sequence representing the SK held by the class"""
        return self.__sk

    def __str__(self):
        """String representation of the class.
        :returns the hexademical """
        return self.__sk.hex()

    def directory(self):
        """:returns the directory in which the files containing the SKs will be stored"""
        return self.DIRECTORY


class PrivateSK(Key):
    """A class representing a private SK
    :param sk: the bytes sequence representing the SK held by the class
    :param n: (Optional) the size in bytes of the SK to generate.
        If not specified, it is set to SK_SIZE"""

    # Directory in which the files containing the private SK will be stored
    DIRECTORY = "not_infected"

    __slots__ = ['__n']

    def __init__(self, n=SK_SIZE):
        """Class constructor.
        Stores in :param n the size in bytes of the SK to generate"""
        self.__n = n
        super().__init__()

    def _get_sk_from_file(self):
        """Reads the private SK from the corresponding file.
        If the file doesn't exist, a new one will be created,
        containing a new SK as a random bytes sequence of size n.
        :return sk: the bytes sequence representing the content of the file storing the SK"""
        path = os.path.join(self.directory(), self.SK_FILE)
        try:
            with open(path, "rb") as f:
                sk = f.read()
        except FileNotFoundError:
            with open(path, "wb") as f:
                sk = token_bytes(self.__n)
                f.write(sk)
        return sk


class PublicSK(Key):
    """A class representing a public SK and the corresponding Public-Private key pairs it is generated from.
    This class uses ECC as key-generation algorithms.
    :param sk: the bytes sequence representing the SK held by the class
    :param curve: the elliptic curve used to generate the keys
    :param x: the x-coordinate of the point on the elliptic curve used to generate the keys
    :param y: the y-coordinate of the point on the elliptic curve used to generate the keys"""

    # Directory in which the files containing the public SK will be stored
    DIRECTORY = "infected"

    # File the private key is stored in
    PRIVATE_KEY_FILE = "private_key_ecc.pem"

    # Size of both x and y points in bytes
    COORDINATE_SIZE = PUBLIC_KEY_SIZE // 2

    # File the public key is stored in
    PUBLIC_KEY_FILE = "public_key_ecc.pem"

    # Format the keys are saved with
    KEY_FORMAT = "PEM"

    __slots__ = ['__curve', '__x', '__y']

    def __init__(self, curve=STANDARD_CURVE):
        """Class constructor.
        Stores in :param curve the elliptic curve used to generate the keys"""
        self.__curve = curve
        super().__init__()

    def x(self):
        """:returns an EccPoint object representing :param x"""
        return self.__x

    def y(self):
        """:returns an EccPoint object representing :param y"""
        return self.__y

    def x_bytes(self):
        """:returns the bytes sequence representing :param x"""
        return int(self.__x).to_bytes(self.COORDINATE_SIZE, 'big')

    def y_bytes(self):
        """:returns the bytes sequence representing :param y"""
        return int(self.__y).to_bytes(self.COORDINATE_SIZE, 'big')

    def _get_sk_from_file(self):
        """Reads the public SK and the ECC-keys from the corresponding files.
        If the file doesn't exist, a new one will be created, containing:
            a new SK = H(x || y) where:
                H is a CRHF
                x is the bytes sequence representing :param x
                y is the bytes sequence representing :param y
                x and y are the coordinates of the point on an elliptic curve used to generate a new pair of keys
            a new ECC-private key
            a new ECC-public key
        Stores x and y as ECCPoint objects in :param x and in :param y
        :return sk: the bytes sequence representing the content of the file storing the SK"""
        sk_path = os.path.join(self.directory(), self.SK_FILE)
        public_key_path = os.path.join(self.directory(), self.PUBLIC_KEY_FILE)
        private_key_path = os.path.join(self.directory(), self.PRIVATE_KEY_FILE)

        try:
            with open(sk_path, "rb") as f:
                sk = f.read()
                key = ECC.import_key(open(private_key_path, "rt").read())
                point = key.pointQ
                self.__x = point.x
                self.__y = point.y
        except FileNotFoundError:
            with open(sk_path, "wb") as f:
                key = ECC.generate(curve=self.__curve)
                with open(private_key_path, "wt") as pkf:
                    pkf.write(key.export_key(format=self.KEY_FORMAT))
                with open(public_key_path, "wt") as pkf:
                    pkf.write(key.public_key().export_key(format=self.KEY_FORMAT))
                point = key.pointQ
                self.__x = point.x
                self.__y = point.y
                x = self.x_bytes()
                y = self.y_bytes()
                sk = x + y
                sk = H(sk)
                f.write(sk)
        return sk

    def private_key_path(self):
        """:returns the file containing the bytes sequence representing the private key"""
        return os.path.join(self.directory(), self.PRIVATE_KEY_FILE)

    def export_public_key(self, file):
        """Appends the concatenation of the bytes sequences representing :param x and :param y in :param file
        :param file: the file in which the public key will be stored"""
        x = self.x_bytes()
        y = self.y_bytes()
        public_key = x + y

        append_if_absent(public_key, PUBLIC_KEY_SIZE, file)

    def get_private_key(self):
        key = ECC.import_key(open(self.private_key_path()).read())
        return key

    @staticmethod
    def construct_public_key(xy):
        """Constructs an ECC-public key starting from the bytes sequences representing the public key.
        :param xy: the bytes sequences representing the public key,
            as of the concatenation of the bytes sequences representing :param x and :param y
        :returns an EccKey object containing the public key corresponding to the couple of coordinates x and y"""
        coordinate_size = len(xy) // 2
        x = int.from_bytes(xy[:coordinate_size], 'big')
        y = int.from_bytes(xy[coordinate_size:], 'big')
        return ECC.construct(curve=STANDARD_CURVE, point_x=x, point_y=y)

    @staticmethod
    def construct_sk(public_key):
        """Computes the SK corresponding to an ECC-public key.
        :param public_key: an EccKey object containing the public key
        :return sk: SK = H(x || y) where:
            H is a CRHF
            x is the bytes sequence representing :param x
            y is the bytes sequence representing :param y
            x and y are the coordinates of the point on an elliptic curve used to generate :param public_key"""
        point = public_key.pointQ
        x = int(point.x).to_bytes(PUBLIC_KEY_SIZE // 2, 'big')
        y = int(point.y).to_bytes(PUBLIC_KEY_SIZE // 2, 'big')
        sk = x + y
        return H(sk)

    @staticmethod
    def get_x_bytes(public_key):
        """:returns a bytes sequence representing :param x"""
        point = public_key.pointQ
        x = int(point.x).to_bytes(PUBLIC_KEY_SIZE // 2, 'big')
        return x

    @staticmethod
    def get_y_bytes(public_key):
        """:returns a bytes sequence representing :param y"""
        point = public_key.pointQ
        y = int(point.y).to_bytes(PUBLIC_KEY_SIZE // 2, 'big')
        return y

    @staticmethod
    def get_public_key_bytes(public_key):
        """:returns the concatenation of the bytes sequences representing :param x and :param y"""
        x = PublicSK.get_x_bytes(public_key)
        y = PublicSK.get_y_bytes(public_key)
        return x + y
