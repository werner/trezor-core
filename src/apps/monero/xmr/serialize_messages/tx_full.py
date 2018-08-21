
from apps.monero.xmr.serialize.base_types import UInt8, UVarintType
from apps.monero.xmr.serialize.erefs import eref
from apps.monero.xmr.serialize.message_types import MessageType
from apps.monero.xmr.serialize_messages.base import ECKey
from apps.monero.xmr.serialize_messages.ct_keys import CtKey, CtkeyM, CtkeyV, KeyM, KeyV
from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhInfo, EcdhTuple
from apps.monero.xmr.serialize_messages.tx_rsig import RctType


class MgSig(MessageType):
    __slots__ = ("ss", "cc", "II")

    @classmethod
    def f_specs(cls):
        return (("ss", KeyM), ("cc", ECKey))


class RctSigBase(MessageType):
    __slots__ = (
        "type",
        "txnFee",
        "message",
        "mixRing",
        "pseudoOuts",
        "ecdhInfo",
        "outPk",
    )

    @classmethod
    def f_specs(cls):
        return (
            ("type", UInt8),
            ("txnFee", UVarintType),
            ("message", ECKey),
            ("mixRing", CtkeyM),
            ("pseudoOuts", KeyV),
            ("ecdhInfo", EcdhInfo),
            ("outPk", CtkeyV),
        )

    async def serialize_rctsig_base(self, ar, inputs, outputs):
        """
        Custom serialization
        :param ar:
        :type ar: x.Archive
        :return:
        """
        await self._msg_field(ar, idx=0)
        if self.type == RctType.Null:
            return
        if (
            self.type != RctType.Full
            and self.type != RctType.FullBulletproof
            and self.type != RctType.Simple
            and self.type != RctType.SimpleBulletproof
        ):
            raise ValueError("Unknown type")

        await self._msg_field(ar, idx=1)
        if self.type == RctType.Simple:
            await ar.prepare_container(inputs, eref(self, "pseudoOuts"), KeyV)
            if ar.writing and len(self.pseudoOuts) != inputs:
                raise ValueError("pseudoOuts size mismatch")

            for i in range(inputs):
                await ar.field(eref(self.pseudoOuts, i), KeyV.ELEM_TYPE)

        await ar.prepare_container(outputs, eref(self, "ecdhInfo"), EcdhTuple)
        if ar.writing and len(self.ecdhInfo) != outputs:
            raise ValueError("EcdhInfo size mismatch")

        for i in range(outputs):
            await ar.field(eref(self.ecdhInfo, i), EcdhInfo.ELEM_TYPE)

        await ar.prepare_container((outputs), eref(self, "outPk"), CtKey)
        if ar.writing and len(self.outPk) != outputs:
            raise ValueError("outPk size mismatch")

        for i in range(outputs):
            await ar.field(eref(self.outPk[i], "mask"), ECKey)
