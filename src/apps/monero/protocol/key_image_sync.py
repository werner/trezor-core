#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import gc
from trezor import log


from apps.monero.controller import wrapper as twrap


class KeyImageSync(object):
    def __init__(self, ctx=None, iface=None, creds=None):
        from apps.monero.xmr import crypto
        from apps.monero.xmr.sub.keccak_hasher import HashWrapper

        self.ctx = ctx
        self.iface = iface
        self.creds = creds  # type: monero.AccountCreds

        self.num = 0
        self.c_idx = -1
        self.hash = None
        self.blocked = None
        self.enc_key = None
        self.subaddresses = {}
        self.hasher = HashWrapper(crypto.get_keccak())

    async def derive_creds(self, msg):
        self.creds = await twrap.monero_get_creds(self.ctx, msg.address_n or (), msg.network_type)

    async def init(self, ctx, msg):
        log.debug(__name__, '### 1Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        from apps.monero.xmr import crypto
        log.debug(__name__, '### 2Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        from apps.monero.xmr import monero
        log.debug(__name__, '### 3Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        from trezor.messages.MoneroRespError import MoneroRespError
        from trezor.messages.MoneroKeyImageExportInitResp import MoneroKeyImageExportInitResp
        log.debug(__name__, '### 4Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

        self.ctx = ctx
        log.debug(__name__, '### 5Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        await self.derive_creds(msg)
        log.debug(__name__, '### 6Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        confirmation = await self.iface.confirm_ki_sync(msg, ctx=ctx)
        if not confirmation:
            return MoneroRespError(reason='rejected')

        self.num = msg.num
        self.hash = msg.hash
        self.enc_key = crypto.random_bytes(32)
        log.debug(__name__, '### 5Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

        # Sub address precomputation
        if msg.subs and len(msg.subs) > 0:
            for sub in msg.subs:  # type: MoneroSubAddrIndicesList
                monero.compute_subaddresses(self.creds, sub.account, sub.minor_indices, self.subaddresses)
        return MoneroKeyImageExportInitResp()

    async def sync(self, ctx, tds):
        from apps.monero.xmr import crypto
        from apps.monero.xmr.enc import chacha_poly
        from apps.monero.xmr import key_image
        from trezor.messages.MoneroExportedKeyImage import MoneroExportedKeyImage
        from trezor.messages.MoneroKeyImageSyncStepResp import MoneroKeyImageSyncStepResp

        log.debug(__name__, 'ki_sync, step i')

        self.ctx = ctx
        if self.blocked:
            raise ValueError('Blocked')
        if len(tds.tdis) == 0:
            raise ValueError('Empty')

        log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        resp = []
        buff = bytearray(32*3)
        buff_mv = memoryview(buff)
        log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

        for td in tds.tdis:
            self.c_idx += 1
            if self.c_idx >= self.num:
                raise ValueError('Too many outputs')

            log.debug(__name__, 'ki_sync, step i: %d', self.c_idx)
            hash = key_image.compute_hash(td)
            log.debug(__name__, 'ki_sync, hash')
            self.hasher.update(hash)
            log.debug(__name__, 'ki_sync, hashed')
            ki, sig = await key_image.export_key_image(self.creds, self.subaddresses, td)
            log.debug(__name__, 'ki_sync, ki')

            crypto.encodepoint_into(ki, buff_mv[0:32])
            crypto.encodeint_into(sig[0][0], buff_mv[32:64])
            crypto.encodeint_into(sig[0][1], buff_mv[64:])
            log.debug(__name__, '### Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

            log.debug(__name__, 'ki_sync, ec: %s', buff)
            nonce, ciph, _ = chacha_poly.encrypt(self.enc_key, buff)
            log.debug(__name__, 'ki_sync, cip')
            eki = MoneroExportedKeyImage(iv=nonce, tag=b'', blob=ciph)
            resp.append(eki)
        log.debug(__name__, 'ki_sync, res')
        return MoneroKeyImageSyncStepResp(kis=resp)

    async def final(self, ctx, msg=None):
        from trezor.messages.MoneroKeyImageSyncFinalResp import MoneroKeyImageSyncFinalResp

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
