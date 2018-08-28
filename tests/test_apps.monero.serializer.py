from common import *
import utest

from trezor import log, loop, utils
from apps.monero.xmr.serialize import xmrserialize as xms
from apps.monero.xmr.serialize.readwriter import MemoryReaderWriter
from apps.monero.xmr.serialize_messages.base import ECPoint
from apps.monero.xmr.serialize_messages.ct_keys import CtKey
from apps.monero.xmr.serialize_messages.tx_prefix import (
    TxinToKey,
    TxinGen,
    TxInV,
    TxOut,
    TxoutToKey,
    TransactionPrefix,
)
from apps.monero.xmr.serialize_messages.tx_rsig_boro import BoroSig
from apps.monero.xmr.serialize_messages.tx_src_entry import OutputEntry


class XmrTstData(object):
    """Simple tests data generator"""

    def __init__(self, *args, **kwargs):
        super(XmrTstData, self).__init__()
        self.ec_offset = 0

    def reset(self):
        self.ec_offset = 0

    def generate_ec_key(self, use_offset=True):
        """
        Returns test EC key, 32 element byte array
        :param use_offset:
        :return:
        """
        offset = 0
        if use_offset:
            offset = self.ec_offset
            self.ec_offset += 1

        return bytearray(range(offset, offset + 32))

    def gen_transaction_prefix(self):
        """
        Returns test transaction prefix
        :return:
        """
        vin = [
            TxinToKey(
                amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
            ),
            TxinToKey(
                amount=456, key_offsets=[9, 8, 7, 6], k_image=bytearray(range(32, 64))
            ),
            TxinGen(height=99),
        ]

        vout = [
            TxOut(amount=11, target=TxoutToKey(key=bytearray(range(32)))),
            TxOut(amount=34, target=TxoutToKey(key=bytearray(range(64, 96)))),
        ]

        msg = TransactionPrefix(
            version=2, unlock_time=10, vin=vin, vout=vout, extra=list(range(31))
        )
        return msg

    def gen_borosig(self):
        """
        Returns a BoroSig message
        :return:
        """
        ee = self.generate_ec_key()
        s0 = [self.generate_ec_key() for _ in range(64)]
        s1 = [self.generate_ec_key() for _ in range(64)]
        msg = BoroSig(s0=s0, s1=s1, ee=ee)
        return msg


class TestMoneroSerializer(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestMoneroSerializer, self).__init__(*args, **kwargs)
        self.tdata = XmrTstData()

    def setUp(self):
        self.tdata.reset()

    async def test_async_varint(self):
        """
        Var int
        :return:
        """
        # fmt: off
        test_nums = [0, 1, 12, 44, 32, 63, 64, 127, 128, 255, 256, 1023, 1024, 8191, 8192,
                     2**16, 2**16 - 1, 2**32, 2**32 - 1, 2**64, 2**64 - 1, 2**72 - 1, 2**112]
        # fmt: on

        for test_num in test_nums:
            writer = MemoryReaderWriter()

            await xms.dump_uvarint(writer, test_num)
            test_deser = await xms.load_uvarint(MemoryReaderWriter(writer.get_buffer()))

            self.assertEqual(test_num, test_deser)

    async def test_async_ecpoint(self):
        """
        Ec point
        :return:
        """
        ec_data = bytearray(range(32))
        writer = MemoryReaderWriter()

        await xms.dump_blob(writer, ec_data, ECPoint)
        self.assertTrue(len(writer.get_buffer()), ECPoint.SIZE)

        test_deser = await xms.load_blob(
            MemoryReaderWriter(writer.get_buffer()), ECPoint
        )
        self.assertEqual(ec_data, test_deser)

    async def test_async_ecpoint_obj(self):
        """
        EC point into
        :return:
        """
        ec_data = bytearray(list(range(32)))
        ec_point = ECPoint()
        ec_point.data = ec_data
        writer = MemoryReaderWriter()

        await xms.dump_blob(writer, ec_point, ECPoint)
        self.assertTrue(len(writer.get_buffer()), ECPoint.SIZE)

        ec_point2 = ECPoint()
        test_deser = await xms.load_blob(
            MemoryReaderWriter(writer.get_buffer()), ECPoint, elem=ec_point2
        )

        self.assertEqual(ec_data, ec_point2.data)
        self.assertEqual(ec_point, ec_point2)

    async def test_async_simple_msg(self):
        """
        TxinGen
        :return:
        """
        msg = TxinGen(height=42)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.message(None, msg_type=TxinGen)
        self.assertEqual(msg.height, test_deser.height)

    async def test_async_simple_msg_into(self):
        """
        TxinGen
        :return:
        """
        msg = TxinGen(height=42)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.message(msg)

        msg2 = TxinGen()
        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.message(msg2, TxinGen)
        self.assertEqual(msg.height, test_deser.height)
        self.assertEqual(msg.height, msg2.height)
        self.assertEqual(msg2, test_deser)

    async def test_async_tuple(self):
        """
        Simple tuple type
        :return:
        """
        out_entry = [
            123,
            CtKey(dest=self.tdata.generate_ec_key(), mask=self.tdata.generate_ec_key()),
        ]
        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)

        await ar1.tuple(out_entry, OutputEntry)
        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.tuple(None, OutputEntry)

        self.assertEqual(out_entry, test_deser)

    async def test_async_txin_to_key(self):
        """
        TxinToKey
        :return:
        """
        msg = TxinToKey(
            amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
        )

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.message(None, TxinToKey)
        self.assertEqual(msg.amount, test_deser.amount)
        self.assertEqual(msg, test_deser)

    async def test_async_txin_variant(self):
        """
        TxInV
        :return:
        """
        msg1 = TxinToKey(
            amount=123, key_offsets=[1, 2, 3, 2 ** 76], k_image=bytearray(range(32))
        )
        msg = TxInV()
        msg.set_variant("txin_to_key", msg1)

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.variant(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.variant(None, TxInV, wrapped=True)
        self.assertEqual(test_deser.__class__, TxInV)
        self.assertEqual(msg, test_deser)
        self.assertEqual(msg.variant_elem, test_deser.variant_elem)
        self.assertEqual(msg.variant_elem_type, test_deser.variant_elem_type)

    async def test_async_tx_prefix(self):
        """
        TransactionPrefix
        :return:
        """
        msg = self.tdata.gen_transaction_prefix()

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.message(None, TransactionPrefix)
        self.assertEqual(test_deser.__class__, TransactionPrefix)
        self.assertEqual(test_deser.version, msg.version)
        self.assertEqual(test_deser.unlock_time, msg.unlock_time)
        self.assertEqual(len(test_deser.vin), len(msg.vin))
        self.assertEqual(len(test_deser.vout), len(msg.vout))
        self.assertEqual(len(test_deser.extra), len(msg.extra))
        self.assertEqual(test_deser.extra, msg.extra)
        self.assertListEqual(test_deser.vin, msg.vin)
        self.assertListEqual(test_deser.vout, msg.vout)
        self.assertEqual(test_deser, msg)

    async def test_async_boro_sig(self):
        """
        BoroSig
        :return:
        """
        msg = self.tdata.gen_borosig()

        writer = MemoryReaderWriter()
        ar1 = xms.Archive(writer, True)
        await ar1.message(msg)

        ar2 = xms.Archive(MemoryReaderWriter(writer.get_buffer()), False)
        test_deser = await ar2.message(None, BoroSig)
        self.assertEqual(msg, test_deser)

    async def test_async_transaction_prefix(self):
        """

        :return:
        """
        tsx_hex = b"013D01FF010680A0DB5002A9243CF5459DE5114E6A1AC08F9180C9F40A3CF9880778878104E9FEA578B6A780A8D6B90702AFEBACD6A4456AF979CCBE08D37A9A670BA421B5E39AB2968DF4219DD086018B8088ACA3CF020251748BADE758D1DD65A867FA3CEDD4878485BBC8307F905E3090A030290672798090CAD2C60E020C823CCBD4AB1A1F9240844400D72CDC8B498B3181B182B0B54A405B695406A680E08D84DDCB01022A9A926097548A723863923FBFEA4913B1134B2E4AE54946268DDA99564B5D8280C0CAF384A30202A868709A8BB91734AD3EBAC127638E018139E375C1987E01CCC2A8B04427727E2101F74BF5FB3DA064F48090D9B6705E598925313875B2B4F2A50EB0517264B0721C"
        tsx_bin = unhexlify(tsx_hex)

        reader = MemoryReaderWriter(bytearray(tsx_bin))
        ar1 = xms.Archive(reader, False)

        test_deser = await ar1.message(None, TransactionPrefix)
        self.assertIsNotNone(test_deser)
        self.assertEqual(len(reader.get_buffer()), 0)  # no data left to read
        self.assertEqual(len(test_deser.extra), 33)
        self.assertEqual(test_deser.extra[0], 1)
        self.assertEqual(test_deser.extra[32], 28)
        self.assertEqual(test_deser.unlock_time, 61)
        self.assertEqual(test_deser.version, 1)
        self.assertEqual(len(test_deser.vin), 1)
        self.assertEqual(len(test_deser.vout), 6)
        self.assertEqual(test_deser.vin[0].height, 1)
        self.assertEqual(test_deser.vout[0].amount, 169267200)
        self.assertEqual(len(test_deser.vout[0].target.key), 32)
        self.assertEqual(test_deser.vout[1].amount, 2000000000)
        self.assertEqual(len(test_deser.vout[1].target.key), 32)
        self.assertEqual(test_deser.vout[5].amount, 10000000000000)
        self.assertEqual(len(test_deser.vout[5].target.key), 32)


if __name__ == "__main__":
    unittest.main()
