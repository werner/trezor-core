import gc
from trezor import log


class MemoryReaderWriter:

    def __init__(self, buffer=None, read_empty=False, threshold=None, do_gc=False, **kwargs):
        self.buffer = buffer
        self.nread = 0
        self.nwritten = 0

        self.ndata = 0
        self.offset = 0
        self.woffset = 0

        self.read_empty = read_empty
        self.threshold = threshold
        self.do_gc = do_gc

        if self.buffer is None:
            self.buffer = bytearray(0)
        else:
            self.woffset = len(buffer)

    def is_empty(self):
        return self.offset == len(self.buffer)

    async def areadinto(self, buf):
        ln = len(buf)
        if not self.read_empty and ln > 0 and len(self.buffer) == 0:
            raise EOFError

        nread = min(ln, len(self.buffer))
        log.debug(__name__, 'read ln=%s, nread=%s', ln, nread)
        for idx in range(nread):
            buf[idx] = self.buffer[self.offset + idx]

        self.offset += nread
        self.nread += nread
        self.ndata -= nread

        # Deallocation threshold triggered
        if self.threshold is not None and self.offset >= self.threshold:
            log.debug(__name__, 'Free ')
            self.buffer = self.buffer[self.offset]
            self.offset = 0

            if self.do_gc:
                gc.collect()

        return nread

    async def awrite(self, buf):
        nwritten = len(buf)
        nall = len(self.buffer)
        nfree = nall - self.woffset
        towrite = nwritten
        bufoff = 0
        log.debug(__name__, 'New writing, buf: %s, nfree: %s, buffree: %s', nwritten, nfree, nfree-towrite)

        # Fill existing place in the buffer
        while towrite > 0 and nall - self.woffset > 0:
            self.buffer[self.woffset] = buf[bufoff]
            self.woffset += 1
            bufoff += 1
            towrite -= 1

        # Allocate next chunk if needed
        if towrite > 0:
            log.debug(__name__, 'New chunk to create, size: %s', towrite)
            chunk = bytearray(32)  # chunk size typical for EC point
            for i in range(towrite):
                chunk[i] = buf[bufoff + i]
                self.woffset += 1

            self.buffer.extend(chunk)
            if self.do_gc:
                chunk = None  # dereference
                gc.collect()

        log.debug(__name__, 'write nwritten=%s, total=%s, off=%s, woff=%s, ln=%s', nwritten, self.nwritten, self.offset, self.woffset, len(self.buffer))
        self.nwritten += nwritten
        self.ndata += nwritten
        return nwritten

    def get_buffer(self):
        mv = memoryview(self.buffer)
        return mv[self.offset:self.woffset]
