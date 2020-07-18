"""
This module contains a method to produce the digest of messages with CRHF.
"""


from Crypto.Hash import SHA256


def H(msg):
    """Returns the SHA-256 digest of msg. Note that everytime you call H, a new instatiation of SHA-256 will be created.
    If you want to produce the digest of A || B, don't use H(A) || H(B), but H(A || B)"""
    h = SHA256.new()
    h.update(msg)
    return h.digest()
