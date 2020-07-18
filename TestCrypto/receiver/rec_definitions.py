"""
This module contains the receiver parameters.
"""

import os


RECEIVER_DIR = os.path.dirname(os.path.abspath(__file__))

# -------------------- RECEIVER PARAMETERS --------------------

# File the public keys of the infected users are stored in
PUBLIC_KEY_INFECTED_FILE = "public_key_infected.pem"

# File the SK of the infected users are stored in
SK_INFECTED_FILE = "sk_infected.pem"

# File the date of the last update of the SK of the infected users is stored in
LAST_SK_INFECTED_UPDATE_FILE = "last_sk_infected_update.txt"

# File the received EphIDs with proper signatures are saved in
EPHID_AND_SIGNATURE_FILE = "ephids.pem"
