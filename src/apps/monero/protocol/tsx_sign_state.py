class TState(object):
    """
    Transaction state
    """
    START = 0
    INIT = 1
    INP_CNT = 2
    INPUT = 3
    INPUT_DONE = 4
    INPUT_PERM = 5
    INPUT_VINS = 6
    OUTPUT = 7
    OUTPUT_DONE = 8
    FINAL_MESSAGE = 9
    SIGNATURE = 10
    SIGNATURE_DONE = 11
    FINAL = 12
    FAIL = 250

    def __init__(self):
        self.s = self.START
        self.in_mem = False

    def init_tsx(self):
        if self.s != self.START:
            raise ValueError('Illegal state')
        self.s = self.INIT

    def inp_cnt(self, in_mem):
        if self.s != self.INIT:
            raise ValueError('Illegal state')
        self.s = self.INP_CNT
        self.in_mem = in_mem

    def input(self):
        if self.s != self.INP_CNT and self.s != self.INPUT:
            raise ValueError('Illegal state')
        self.s = self.INPUT

    def input_done(self):
        if self.s != self.INPUT:
            raise ValueError('Illegal state')
        self.s = self.INPUT_DONE

    def input_permutation(self):
        if self.s != self.INPUT_DONE:
            raise ValueError('Illegal state')
        self.s = self.INPUT_PERM

    def input_vins(self):
        if self.s != self.INPUT_PERM and self.s != self.INPUT_VINS:
            raise ValueError('Illegal state')
        self.s = self.INPUT_VINS

    def is_input_vins(self):
        return self.s == self.INPUT_VINS

    def set_output(self):
        if ((not self.in_mem and self.s != self.INPUT_VINS)
            or (self.in_mem and self.s != self.INPUT_PERM)) \
                and self.s != self.OUTPUT:
            raise ValueError('Illegal state')
        self.s = self.OUTPUT

    def set_output_done(self):
        if self.s != self.OUTPUT:
            raise ValueError('Illegal state')
        self.s = self.OUTPUT_DONE

    def set_final_message_done(self):
        if self.s != self.OUTPUT_DONE:
            raise ValueError('Illegal state')
        self.s = self.FINAL_MESSAGE

    def set_signature(self):
        if self.s != self.FINAL_MESSAGE and self.s != self.SIGNATURE:
            raise ValueError('Illegal state')
        self.s = self.SIGNATURE

    def set_signature_done(self):
        if self.s != self.SIGNATURE:
            raise ValueError('Illegal state')
        self.s = self.SIGNATURE_DONE

    def set_final(self):
        if self.s != self.SIGNATURE_DONE:
            raise ValueError('Illegal state')
        self.s = self.FINAL

    def set_fail(self):
        self.s = self.FAIL

    def is_terminal(self):
        return self.s in [self.FINAL, self.FAIL]
