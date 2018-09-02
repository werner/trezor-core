from micropython import const

from trezor.crypto import base58, chacha20poly1305, crc, hashlib, pbkdf2

from . import cbor

from apps.common import HARDENED, seed


def validate_full_path(path: list) -> bool:
    """
    Validates derivation path to fit 44'/1815'/a'/{0,1}/i,
    where `a` is an account number and i an address index.
    The max value for `a` is 10, 1 000 000 for `i`.
    The derivation scheme v1 allows a'/0/i only,
    but in v2 it can be a'/1/i as well.
    """
    if len(path) != 5:
        return False
    if path[0] != 44 | HARDENED:
        return False
    if path[1] != 1815 | HARDENED:
        return False
    if path[2] < HARDENED or path[2] > 10 | HARDENED:
        return False
    if path[3] != 0 and path[3] != 1:
        return False
    if path[4] > 1000000:
        return False
    return True


def _derive_hd_passphrase(node) -> bytes:
    iterations = const(500)
    length = const(32)
    passwd = seed.remove_ed25519_prefix(node.public_key()) + node.chain_code()
    x = pbkdf2("hmac-sha512", passwd, b"address-hashing", iterations)
    return x.key()[:length]


def _address_hash(data) -> bytes:
    data = cbor.encode(data)
    data = hashlib.sha3_256(data).digest()
    res = hashlib.blake2b(data=data, outlen=28).digest()
    return res


def _get_address_root(node, payload):
    extpubkey = seed.remove_ed25519_prefix(node.public_key()) + node.chain_code()
    if payload:
        payload = {1: cbor.encode(payload)}
    else:
        payload = {}
    return _address_hash([0, [0, extpubkey], payload])


def _encrypt_derivation_path(path: list, hd_passphrase: bytes) -> bytes:
    serialized = cbor.encode(cbor.IndefiniteLengthArray(path))
    ctx = chacha20poly1305(hd_passphrase, b"serokellfore")
    data = ctx.encrypt(serialized)
    tag = ctx.finish()
    return data + tag


def derive_address_and_node(root_node, path: list):
    derived_node = root_node.clone()

    # this means empty derivation path m/44'/1815'
    if len(path) == 2:
        address_payload = None
        address_attributes = {}
    else:
        if len(path) == 5:
            p = [path[2], path[4]]
        else:
            p = [path[2]]
        for indice in p:
            derived_node.derive_cardano(indice)

        hd_passphrase = _derive_hd_passphrase(root_node)
        address_payload = _encrypt_derivation_path(p, hd_passphrase)
        address_attributes = {1: cbor.encode(address_payload)}

    address_root = _get_address_root(derived_node, address_payload)
    address_type = 0
    address_data = [address_root, address_attributes, address_type]
    address_data_encoded = cbor.encode(address_data)

    address = base58.encode(
        cbor.encode(
            [cbor.Tagged(24, address_data_encoded), crc.crc32(address_data_encoded)]
        )
    )
    return (address, derived_node)
