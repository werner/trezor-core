from apps.monero.xmr.serialize.message_types import MessageType, ContainerType
from apps.monero.xmr.serialize.messages.base import ECKey


class EcdhTuple(MessageType):
    __slots__ = ['mask', 'amount']
    MFIELDS = [
        ('mask', ECKey),
        ('amount', ECKey),
    ]


class EcdhInfo(ContainerType):
    ELEM_TYPE = EcdhTuple
