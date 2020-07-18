"""
This module contains the sender parameters.
"""


import os


SENDER_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- SENDER PARAMETERS --------------------

# File the ciphertext (IV + N EphIDs) will be saved in
CIPHERTEXT_FILE = "ciphertext.pem"

# File the date of the last update of the ciphertext is stored in
LAST_CIPHERTEXT_UPDATE_FILE = "last_ciphertext_update.txt"
