/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/objstr.h"

#include "monero/monero.h"

typedef struct _mp_obj_hasher_t {
  mp_obj_base_t base;
  Hasher h;
} mp_obj_hasher_t;

typedef struct _mp_obj_ge25519_t {
    mp_obj_base_t base;
    ge25519 p;
} mp_obj_ge25519_t;

typedef struct _mp_obj_bignum256modm_t {
    mp_obj_base_t base;
    bignum256modm p;
} mp_obj_bignum256modm_t;

typedef struct _mp_obj_xmr_range_sig_t {
    mp_obj_base_t base;
    xmr_range_sig_t r;
    ge25519 C;
    bignum256modm m;
} mp_obj_xmr_range_sig_t;


STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_monero) },
    // { MP_ROM_QSTR(MP_QSTR_cosi_sign), MP_ROM_PTR(&mod_trezorcrypto_ed25519_cosi_sign_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_globals, mod_trezorcrypto_monero_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_monero_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_monero_globals,
};
