from micropython import const

from apps.monero.xmr.serialize.messages.base import ECPublicKey, Hash, KeyImage
from apps.monero.xmr.serialize.base_types import UInt8, UVarintType
from apps.monero.xmr.serialize.message_types import MessageType, VariantType, ContainerType, BlobType

_c0 = const(0)
_c1 = const(1)
_c32 = const(32)
_c64 = const(64)


class TxoutToScript(MessageType):
    __slots__ = ['keys', 'script']
    VARIANT_CODE = 0x0
    MFIELDS = [
        ('keys', ContainerType, ECPublicKey),
        ('script', ContainerType, UInt8),
    ]


class TxoutToKey(MessageType):
    __slots__ = ['key']
    VARIANT_CODE = 0x2
    MFIELDS = [
        ('key', ECPublicKey),
    ]


class TxoutToScriptHash(MessageType):
    __slots__ = ['hash']
    VARIANT_CODE = 0x1
    MFIELDS = [
        ('hash', Hash),
    ]


class TxoutTargetV(VariantType):
    MFIELDS = [
        ('txout_to_script', TxoutToScript),
        ('txout_to_scripthash', TxoutToScriptHash),
        ('txout_to_key', TxoutToKey),
    ]


class TxinGen(MessageType):
    __slots__ = ['height']
    VARIANT_CODE = 0xff
    MFIELDS = [
        ('height', UVarintType),
    ]


class TxinToKey(MessageType):
    __slots__ = ['amount', 'key_offsets', 'k_image']
    VARIANT_CODE = 0x2
    MFIELDS = [
        ('amount', UVarintType),
        ('key_offsets', ContainerType, UVarintType),
        ('k_image', KeyImage),
    ]


class TxinToScript(MessageType):
    __slots__ = []
    VARIANT_CODE = _c0
    MFIELDS = []


class TxinToScriptHash(MessageType):
    __slots__ = []
    VARIANT_CODE = _c1
    MFIELDS = []


class TxInV(VariantType):
    MFIELDS = [
        ('txin_gen', TxinGen),
        ('txin_to_script', TxinToScript),
        ('txin_to_scripthash', TxinToScriptHash),
        ('txin_to_key', TxinToKey),
    ]


class TxOut(MessageType):
    __slots__ = ['amount', 'target']
    MFIELDS = [
        ('amount', UVarintType),
        ('target', TxoutTargetV),
    ]


class TransactionPrefix(MessageType):
    MFIELDS = [
        ('version', UVarintType),
        ('unlock_time', UVarintType),
        ('vin', ContainerType, TxInV),
        ('vout', ContainerType, TxOut),
        ('extra', ContainerType, UInt8),
    ]


class TransactionPrefixExtraBlob(TransactionPrefix):
    # noinspection PyTypeChecker
    MFIELDS = TransactionPrefix.MFIELDS[:-1] + [
        ('extra', BlobType),
    ]
