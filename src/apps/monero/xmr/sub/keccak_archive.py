from apps.monero.xmr import common, crypto
from apps.monero.xmr.serialize import xmrserialize


class KeccakArchive(object):
    def __init__(self):
        self.kwriter = get_keccak_writer()
        self.ar = xmrserialize.Archive(self.kwriter, True)


def get_keccak_writer(sub_writer=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :return:
    """
    return common.AHashWriter(common.HashWrapper(crypto.get_keccak()), sub_writer=sub_writer)
