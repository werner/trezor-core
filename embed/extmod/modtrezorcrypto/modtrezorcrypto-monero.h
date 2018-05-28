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
#include "py/objint.h"
#include "py/mpz.h"

#include "monero/monero.h"
#define RSIG_SIZE 6176

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

typedef union {
  xmr_range_sig_t r;
  unsigned char d[RSIG_SIZE];
} rsig_union;

typedef struct _mp_obj_xmr_range_sig_t {
    mp_obj_base_t base;
    union {
      xmr_range_sig_t r;
      unsigned char d[RSIG_SIZE];
    } rsig;
    ge25519 C;
    bignum256modm m;
} mp_obj_xmr_range_sig_t;


//
// Helpers
//

STATIC const mp_obj_type_t mod_trezorcrypto_monero_ge25519_type;
STATIC const mp_obj_type_t mod_trezorcrypto_monero_bignum256modm_type;


static uint64_t mp_obj_uint64_get_checked(mp_const_obj_t self_in) {
    if (MP_OBJ_IS_SMALL_INT(self_in)) {
        return MP_OBJ_SMALL_INT_VALUE(self_in);
    } else {  // TODO: LONGLONG IMPL IFDEF
        byte buff[8];
        uint64_t res = 0;
        mp_obj_t * o = MP_OBJ_TO_PTR(self_in);

        mp_obj_int_to_bytes_impl(MP_OBJ_FROM_PTR(o), false, 8, buff);
        for (int i = 0; i<8; i++){
            res <<= i*8;
            res |= buff[i] & 0xff;
        }
        return res;
    }
}

static uint64_t mp_obj_get_uint64(mp_const_obj_t arg) {
    if (arg == mp_const_false) {
        return 0;
    } else if (arg == mp_const_true) {
        return 1;
    } else if (MP_OBJ_IS_SMALL_INT(arg)) {
        return MP_OBJ_SMALL_INT_VALUE(arg);
    } else if (MP_OBJ_IS_TYPE(arg, &mp_type_int)) {
        return mp_obj_uint64_get_checked(arg);
    } else {
        if (MICROPY_ERROR_REPORTING == MICROPY_ERROR_REPORTING_TERSE) {
            mp_raise_TypeError("can't convert to int");
        } else {
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_TypeError,
                                                    "can't convert %s to int", mp_obj_get_type_str(arg)));
        }
    }
}

STATIC mp_obj_t mp_obj_from_scalar(const bignum256modm in){
    mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
    o->base.type = &mod_trezorcrypto_monero_bignum256modm_type;
    memcpy(&o->p, in, sizeof(bignum256modm));
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_from_ge25519(const ge25519 * in){
    mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
    o->base.type = &mod_trezorcrypto_monero_ge25519_type;
    memcpy(&o->p, in, sizeof(ge25519));
    return MP_OBJ_FROM_PTR(o);
}

//
// Defs
//

/// def
STATIC mp_obj_t mod_trezorcrypto_monero_gen_range_proof(size_t n_args, const mp_obj_t *args) {
    uint64_t amount;
    xmr_range_sig_t rsig;
    ge25519 C;
    bignum256modm mask;
    mp_obj_bignum256modm_t * last_mask = NULL;

    amount = mp_obj_get_uint64(args[0]);
    if (n_args > 1){
        last_mask = MP_OBJ_TO_PTR(args[1]);
    }

    xmr_gen_range_sig(&rsig, &C, mask, amount, last_mask ? &(last_mask->p) : NULL);
    rsig_union rsigun = (rsig_union)rsig;

    mp_obj_tuple_t *tuple = MP_OBJ_TO_PTR(mp_obj_new_tuple(3, NULL));
    tuple->items[0] = mp_obj_from_ge25519(&C);
    tuple->items[1] = mp_obj_from_scalar(mask);
    tuple->items[2] = mp_obj_new_bytes(rsigun.d, RSIG_SIZE);
    return MP_OBJ_FROM_PTR(tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_gen_range_proof_obj, 1, 2, mod_trezorcrypto_monero_gen_range_proof);


//
// Type defs
//


STATIC const mp_obj_type_t mod_trezorcrypto_monero_ge25519_type = {
    { &mp_type_type },
    .name = MP_QSTR_ge25519,
    //.make_new = mod_trezorcrypto_Sha512_make_new,
    //.locals_dict = (void*)&mod_trezorcrypto_Sha512_locals_dict,
};

STATIC const mp_obj_type_t mod_trezorcrypto_monero_bignum256modm_type = {
    { &mp_type_type },
    .name = MP_QSTR_bignum256modm,
//    .make_new = mod_trezorcrypto_Sha512_make_new,
//    .locals_dict = (void*)&mod_trezorcrypto_Sha512_locals_dict,
};


STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_monero) },
    // { MP_ROM_QSTR(MP_QSTR_cosi_sign), MP_ROM_PTR(&mod_trezorcrypto_ed25519_cosi_sign_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_globals, mod_trezorcrypto_monero_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_monero_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_monero_globals,
};
