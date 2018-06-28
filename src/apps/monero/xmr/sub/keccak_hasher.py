from apps.monero.xmr import crypto
from apps.monero.xmr.serialize import xmrserialize


class KeccakArchive(object):
    def __init__(self):
        self.kwriter = get_keccak_writer()
        self.ar = xmrserialize.Archive(self.kwriter, True)


class HashWrapper(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def update(self, buf):
        if len(buf) == 0:
            return
        if isinstance(buf, bytearray):
            self.ctx.update(bytes(buf))  # TODO: optimize
        else:
            self.ctx.update(buf)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()


class AHashWriter:
    def __init__(self, hasher, sub_writer=None):
        self.hasher = hasher
        self.sub_writer = sub_writer

    async def awrite(self, buf):
        self.hasher.update(buf)
        if self.sub_writer:
            await self.sub_writer.awrite(buf)
        return len(buf)

    def get_digest(self, *args) -> bytes:
        return self.hasher.digest(*args)


def get_keccak_writer(sub_writer=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :return:
    """
    return AHashWriter(HashWrapper(crypto.get_keccak()), sub_writer=sub_writer)
