from apps.monero.xmr.serialize.base_types import UVarintType, BoolType
from apps.monero.xmr.serialize.message_types import MessageType
from apps.monero.xmr.serialize_messages.addr import AccountPublicAddress


class TxDestinationEntry(MessageType):
    __slots__ = ['amount', 'addr', 'is_subaddress']
    MFIELDS = [
        ('amount', UVarintType),  # original: UInt64
        ('addr', AccountPublicAddress),
        ('is_subaddress', BoolType),
    ]
