from trezor.crypto import aes


def encrypt(key, plaintext, iv=None):
    """
    Uses AES-CBC for encryption
    """
    ctx = aes(aes.CBC, key, iv)
    return ctx.encrypt(plaintext)


def decrypt(key, ciphertext, iv=None):
    """
    AES-CBC decryption
    """
    ctx = aes(aes.CBC, key, iv)
    return ctx.decrypt(ciphertext)
