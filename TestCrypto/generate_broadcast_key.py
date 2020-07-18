#! /bin/python3

import sys
sys.path.append('../TestCrypto')

from secrets import token_bytes

from cipher import BROADCAST_KEY_FILE, BROADCAST_KEY_SIZE


if __name__ == '__main__':
    """If the Broadcast Key doesn't exist, or it has a different lenght (due to a prior configuration), it is newly
    generated as a random bytes sequence."""
    try:
        with open(BROADCAST_KEY_FILE, "rb") as f:
            if len(f.read()) != BROADCAST_KEY_SIZE:
                raise ValueError
    except (FileNotFoundError, ValueError):
        with open(BROADCAST_KEY_FILE, "wb") as f:
            f.write(token_bytes(BROADCAST_KEY_SIZE))
