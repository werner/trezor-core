#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from trezor.crypto import random
from trezor.crypto.chacha20poly1305 import ChaCha20Poly1305


def encrypt(key, plaintext, associated_data=None):
    """
    Uses ChaCha20Poly1305 for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """
    nonce = random.bytes(12)
    cipher = ChaCha20Poly1305(key, nonce)
    if associated_data:
        cipher.auth(associated_data)
    ciphertext = cipher.encrypt(plaintext)
    return nonce, ciphertext, b''


def decrypt(key, iv, ciphertext, tag=None, associated_data=None):
    """
    ChaCha20Poly1305 decryption
    :param key:
    :param iv:
    :param ciphertext:
    :param tag:
    :param associated_data:
    :return:
    """
    cipher = ChaCha20Poly1305(iv, key)
    if associated_data:
        cipher.auth(associated_data)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext




