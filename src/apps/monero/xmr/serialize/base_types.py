class XmrType:
    VERSION = 0


class UVarintType(XmrType):
    pass


class IntType(XmrType):
    WIDTH = 0
    SIGNED = 0
    VARIABLE = 0


class BoolType(IntType):
    WIDTH = 1


class UInt8(IntType):
    WIDTH = 1


class UInt32(IntType):
    WIDTH = 4


class UInt64(IntType):
    WIDTH = 8


class SizeT(UInt64):
    WIDTH = 8
