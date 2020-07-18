"""
This module contains the secure communication protocol parameters.
"""

import os


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- GENERAL PROTOCOL PARAMETERS --------------------

# Size of SK in bytes
SK_SIZE = 32

# Number of minutes after which a new EphID is sent in broadcast
L = 10

# Number of EphIDs generated each day
N = 24 * 60 // L
