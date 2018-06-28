from apps.monero.xmr.serialize.base_types import UVarintType, SizeT, UInt64, BoolType
from apps.monero.xmr.serialize.message_types import MessageType, TupleType, ContainerType
from apps.monero.xmr.serialize_messages.base import ECKey, ECPublicKey
from apps.monero.xmr.serialize_messages.ct_keys import CtKey


class MultisigKLRki(MessageType):
    MFIELDS = [
        ('K', ECKey),
        ('L', ECKey),
        ('R', ECKey),
        ('ki', ECKey),
    ]


class OutputEntry(TupleType):
    MFIELDS = [
        UVarintType, CtKey  # original: x.UInt64
    ]


class TxSourceEntry(MessageType):
    MFIELDS = [
        ('outputs', ContainerType, OutputEntry),
        ('real_output', SizeT),
        ('real_out_tx_key', ECPublicKey),
        ('real_out_additional_tx_keys', ContainerType, ECPublicKey),
        ('real_output_in_tx_index', UInt64),
        ('amount', UInt64),
        ('rct', BoolType),
        ('mask', ECKey),
        ('multisig_kLRki', MultisigKLRki),
    ]
