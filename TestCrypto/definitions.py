"""
This module contains the cryptografic tools parameters.
"""

import os

from cipher import BLOCK_SIZE


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- ENCRYPTION SCHEME PARAMETERS --------------------

# IV size of the cipher in bytes
IV_SIZE = BLOCK_SIZE

# Size of a EphID in bytes
EPHID_SIZE = BLOCK_SIZE

# -------------------- SIGNATURE SCHEME PARAMETERS --------------------

# Standard used to sign and verify messages: https://tools.ietf.org/html/rfc6979
STANDARD = 'deterministic-rfc6979'

# Curve used to generate the public key
STANDARD_CURVE = 'P-256'

# Signature size of the signature scheme in bytes. Change it if you change the curve
SIGNATURE_SIZE = 64

# -------------------- GENERAL COMMUNICATION PARAMETERS --------------------

# Size in bytes of a to-send BLE packet (IV + EphID + tag)
PACKET_SIZE = IV_SIZE + EPHID_SIZE + SIGNATURE_SIZE
