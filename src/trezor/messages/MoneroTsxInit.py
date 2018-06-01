# Automatically generated by pb2py
import protobuf as p
if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None
from .MoneroTsxData import MoneroTsxData


class MoneroTsxInit(p.MessageType):
    FIELDS = {
        1: ('version', p.UVarintType, 0),
        2: ('address_n', p.UVarintType, p.FLAG_REPEATED),
        3: ('tsx_data', MoneroTsxData, 0),
    }

    def __init__(
        self,
        version: int = None,
        address_n: List[int] = None,
        tsx_data: MoneroTsxData = None
    ) -> None:
        self.version = version
        self.address_n = address_n if address_n is not None else []
        self.tsx_data = tsx_data