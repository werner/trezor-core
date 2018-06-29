from trezor import log


class MemoryReaderWriter:

    def __init__(self, buffer=None, read_empty=False, **kwargs):
        self.buffer = buffer if buffer else bytearray(32)
        self.nread = 0
        self.nwritten = 0
        self.offset = 0
        self.read_empty = read_empty

    async def areadinto(self, buf):
        ln = len(buf)
        if not self.read_empty and ln > 0 and len(self.buffer) == 0:
            raise EOFError

        nread = min(ln, len(self.buffer))
        log.debug(__name__, 'read ln=%s, nread=%s', ln, nread)
        for idx in range(nread):
            buf[idx] = self.buffer[idx]

        self.buffer = self.buffer[nread:]
        self.nread += nread
        return nread

    async def awrite(self, buf):
        self.buffer.extend(buf)
        nwritten = len(buf)
        log.debug(__name__, 'write nwritten=%s, total=%s', nwritten, self.nwritten)
        self.nwritten += nwritten
        return nwritten

    def get_buffer(self):
        return self.buffer
