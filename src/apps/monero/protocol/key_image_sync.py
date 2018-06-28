#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from apps.monero.xmr import monero, crypto, common, key_image
from apps.monero.xmr.enc import chacha_poly
from apps.monero.controller import wrapper as twrap

from apps.monero.messages import MoneroExportedKeyImage, \
    MoneroKeyImageExportInit, MoneroKeyImageExportInitResp, \
    MoneroKeyImageSyncStep, MoneroKeyImageSyncStepResp, \
    MoneroKeyImageSyncFinalResp, \
    MoneroRespError


class KeyImageSync(object):
    def __init__(self, ctx=None, iface=None, creds=None):
        self.ctx = ctx
        self.iface = iface
        self.creds = creds  # type: monero.AccountCreds

        self.num = 0
        self.c_idx = -1
        self.hash = None
        self.blocked = None
        self.enc_key = None
        self.subaddresses = {}
        self.hasher = common.HashWrapper(crypto.get_keccak())

    async def derive_creds(self, msg: MoneroKeyImageExportInit):
        self.creds = await twrap.monero_get_creds(self.ctx, msg.address_n or (), msg.network_type)

    async def init(self, ctx, msg: MoneroKeyImageExportInit):
        self.ctx = ctx
        await self.derive_creds(msg)

        confirmation = await self.iface.confirm_ki_sync(msg, ctx=ctx)
        if not confirmation:
            return MoneroRespError(reason='rejected')

        self.num = msg.num
        self.hash = msg.hash
        self.enc_key = crypto.random_bytes(32)

        # Sub address precomputation
        if msg.subs and len(msg.subs) > 0:
            for sub in msg.subs:  # type: MoneroSubAddrIndicesList
                monero.compute_subaddresses(self.creds, sub.account, sub.minor_indices, self.subaddresses)
        return MoneroKeyImageExportInitResp()

    async def sync(self, ctx, tds: MoneroKeyImageSyncStep):
        self.ctx = ctx
        if self.blocked:
            raise ValueError('Blocked')
        if len(tds.tdis) == 0:
            raise ValueError('Empty')
        resp = []
        buff = bytearray(32*3)
        buff_mv = memoryview(buff)
        for td in tds.tdis:
            self.c_idx += 1
            if self.c_idx >= self.num:
                raise ValueError('Too many outputs')

            hash = key_image.compute_hash(td)
            self.hasher.update(hash)

            ki, sig = await key_image.export_key_image(self.creds, self.subaddresses, td)

            crypto.encodepoint_into(ki, buff_mv[0:32])
            crypto.encodeint_into(sig[0][0], buff_mv[32:64])
            crypto.encodeint_into(sig[0][1], buff_mv[64:])

            nonce, ciph, _ = chacha_poly.encrypt(self.enc_key, buff)
            eki = MoneroExportedKeyImage(iv=nonce, tag=b'', blob=ciph)
            resp.append(eki)
        return MoneroKeyImageSyncStepResp(kis=resp)

    async def final(self, ctx, msg=None):
        self.ctx = ctx
        if self.blocked:
            raise ValueError('Blocked')

        if self.c_idx + 1 != self.num:
            await self.iface.ki_error('Invalid number of outputs', ctx=self.ctx)
            raise ValueError('Invalid number of outputs')

        final_hash = self.hasher.digest()
        if final_hash != self.hash:
            await self.iface.ki_error('Invalid hash', ctx=self.ctx)
            raise ValueError('Invalid hash')

        return MoneroKeyImageSyncFinalResp(enc_key=self.enc_key)
