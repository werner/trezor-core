from trezor.crypto import monero


class XmrException(Exception):
    pass


def ct_equal(a, b):
    return monero.ct_equals(a, b)


def check_permutation(permutation):
    for n in range(len(permutation)):
        if n not in permutation:
            raise ValueError("Invalid permutation")


def apply_permutation(permutation, swapper):
    """
    Apply permutation from idx. Used for in-place permutation application with swapper.
    Ported from Monero.
    :param permutation:
    :param swapper: function(x,y)
    :return:
    """
    check_permutation(permutation)
    perm = list(permutation)
    for i in range(len(perm)):
        current = i
        while i != perm[current]:
            nxt = perm[current]
            swapper(current, nxt)
            perm[current] = current
            current = nxt
        perm[current] = current


def is_empty(inp):
    return inp is None or len(inp) == 0


def defval_empty(val, default=None):
    return val if not is_empty(val) else default
