class MemoryReaderWriter:

    def __init__(self, buffer=None, read_empty=False, **kwargs):
        self.buffer = buffer if buffer else []
        self.nread = 0
        self.nwritten = 0
        self.read_empty = read_empty

    async def areadinto(self, buf):
        ln = len(buf)
        if not self.read_empty and ln > 0 and len(self.buffer) == 0:
            raise EOFError

        nread = min(ln, len(self.buffer))
        for idx in range(nread):
            buf[idx] = self.buffer[idx]
        self.buffer = self.buffer[nread:]
        self.nread += nread
        return nread

    async def awrite(self, buf):
        self.buffer.extend(buf)
        nwritten = len(buf)
        self.nwritten += nwritten
        return nwritten