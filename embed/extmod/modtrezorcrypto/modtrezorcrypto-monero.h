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

STATIC mp_obj_t mp_obj_new_scalar(){
  mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
  o->base.type = &mod_trezorcrypto_monero_bignum256modm_type;
  set256_modm(o->p, 0);
  return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_new_ge25519(){
  mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
  o->base.type = &mod_trezorcrypto_monero_ge25519_type;
  ge25519_set_neutral(&o->p);
  return MP_OBJ_FROM_PTR(o);
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

STATIC void mp_unpack_ge25519(ge25519 * r, const mp_obj_t arg){
    mp_buffer_info_t buff;
    mp_get_buffer_raise(arg, &buff, MP_BUFFER_READ);
    if (buff.len != 32) {
        mp_raise_ValueError("Invalid length of the EC point");
    }

    const int res = ge25519_unpack_vartime(r, buff.buf);
    if (res != 1){
        mp_raise_ValueError("Point decoding error");
    }
}

STATIC void mp_unpack_scalar(bignum256modm r, const mp_obj_t arg){
    mp_buffer_info_t buff;
    mp_get_buffer_raise(arg, &buff, MP_BUFFER_READ);
    if (buff.len < 32 || buff.len > 64) {
        mp_raise_ValueError("Invalid length of secret key");
    }
    expand256_modm(r, buff.buf, buff.len);
}

#define MP_OBJ_IS_GE25519(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_monero_ge25519_type)
#define MP_OBJ_IS_SCALAR(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_monero_bignum256modm_type)
#define MP_OBJ_PTR_MPC_GE25519(o) ((const mp_obj_ge25519_t*) (o))
#define MP_OBJ_PTR_MPC_SCALAR(o) ((const mp_obj_bignum256modm_t*) (o))
#define MP_OBJ_PTR_MP_GE25519(o) ((mp_obj_ge25519_t*) (o))
#define MP_OBJ_PTR_MP_SCALAR(o) ((mp_obj_bignum256modm_t*) (o))
#define MP_OBJ_C_GE25519(o) (MP_OBJ_PTR_MPC_GE25519(o)->p)
#define MP_OBJ_GE25519(o) (MP_OBJ_PTR_MP_GE25519(o)->p)
#define MP_OBJ_C_SCALAR(o) (MP_OBJ_PTR_MPC_SCALAR(o)->p)
#define MP_OBJ_SCALAR(o) (MP_OBJ_PTR_MP_SCALAR(o)->p)

STATIC inline void assert_ge25519(const mp_obj_t o){
    if (!MP_OBJ_IS_GE25519(o)){
        mp_raise_ValueError("ge25519 expected");
    }
}

STATIC inline void assert_scalar(const mp_obj_t o){
    if (!MP_OBJ_IS_SCALAR(o)){
        mp_raise_ValueError("scalar expected");
    }
}

//
// Constructors
//


STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_ge25519_t *o = m_new_obj(mp_obj_ge25519_t);
    o->base.type = type;

    if (n_args == 0) {
        ge25519_set_neutral(&o->p);
    } else if (n_args == 1 && MP_OBJ_IS_GE25519(args[0])) {
        ge25519_copy(&o->p, &MP_OBJ_C_GE25519(args[0]));
    } else if (n_args == 1 && MP_OBJ_IS_STR_OR_BYTES(args[0])) {
        mp_unpack_ge25519(&o->p, args[0]);
    } else {
        mp_raise_ValueError("Invalid ge25519 constructor");
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_monero_bignum256modm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_bignum256modm_t *o = m_new_obj(mp_obj_bignum256modm_t);
    o->base.type = type;

    if (n_args == 0) {
        set256_modm(o->p, 0);
    } else if (n_args == 1 && MP_OBJ_IS_SCALAR(args[0])) {
        copy256_modm(o->p, MP_OBJ_C_SCALAR(args[0]));
    } else if (n_args == 1 && MP_OBJ_IS_STR_OR_BYTES(args[0])) {
        mp_unpack_scalar(o->p, args[0]);
    } else if (n_args == 1 && mp_obj_is_integer(args[0])) {
        uint64_t v = mp_obj_get_uint64(args[0]);
        set256_modm(o->p, v);
    } else {
        mp_raise_ValueError("Invalid scalar constructor");
    }

    return MP_OBJ_FROM_PTR(o);
}

//
// Scalar defs
//

// init256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_init256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 2 ? 0 : -1;
    assert_scalar(res);

    if (n_args == 0) {
        set256_modm(MP_OBJ_SCALAR(res), 0);
    } else if (n_args > 0 && MP_OBJ_IS_SCALAR(args[1+off])) {
        copy256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]));
    } else if (n_args > 0 && MP_OBJ_IS_STR_OR_BYTES(args[1+off])) {
        mp_unpack_scalar(MP_OBJ_SCALAR(res), args[1+off]);
    } else if (n_args > 0 && mp_obj_is_integer(args[1+off])) {
        uint64_t v = mp_obj_get_uint64(args[1+off]);
        set256_modm(MP_OBJ_SCALAR(res), v);
    } else {
        mp_raise_ValueError("Invalid scalar def");
    }
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_init256_modm_obj, 0, 2, mod_trezorcrypto_monero_init256_modm);

//int check256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_check256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    if (check256_modm(MP_OBJ_C_SCALAR(arg)) != 1){
        mp_raise_ValueError("Ed25519 scalar invalid");
    }
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_check256_modm_obj, mod_trezorcrypto_monero_check256_modm);

//int iszero256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_iszero256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    const int r = iszero256_modm(MP_OBJ_C_SCALAR(arg));
    return mp_obj_new_int(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_iszero256_modm_obj, mod_trezorcrypto_monero_iszero256_modm);

//int eq256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_eq256_modm(const mp_obj_t a, const mp_obj_t b){
    assert_scalar(a);
    assert_scalar(b);
    int r = eq256_modm(MP_OBJ_C_SCALAR(a), MP_OBJ_C_SCALAR(b));
    return MP_OBJ_NEW_SMALL_INT(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_eq256_modm_obj, mod_trezorcrypto_monero_eq256_modm);

//int get256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_get256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    uint64_t v;
    if (!get256_modm(&v, MP_OBJ_C_SCALAR(arg))){
        mp_raise_ValueError("Ed25519 scalar too big");
    }
    return mp_obj_new_int_from_ull(v);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_get256_modm_obj, mod_trezorcrypto_monero_get256_modm);

// barrett_reduce256_modm_r, 1arg = lo, 2args = hi, lo, 3args = r, hi, lo
STATIC mp_obj_t mod_trezorcrypto_monero_reduce256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;
    const bignum256modm hi_z = {0};
    const bignum256modm *hi = &hi_z;
    const bignum256modm *lo = NULL;

    assert_scalar(res);
    if (n_args > 1){
        assert_scalar(args[2+off]);
        lo = &MP_OBJ_C_SCALAR(args[2+off]);

        if (args[1+off] == NULL || MP_OBJ_IS_TYPE(args[1+off], &mp_type_NoneType)){
            ;
        } else {
            assert_scalar(args[1+off]);
            hi = &MP_OBJ_C_SCALAR(args[1+off]);
        }
    } else {
        assert_scalar(args[1+off]);
        lo = &MP_OBJ_C_SCALAR(args[1+off]);
    }

    barrett_reduce256_modm(MP_OBJ_SCALAR(res), *hi, *lo);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_reduce256_modm_obj, 1, 3, mod_trezorcrypto_monero_reduce256_modm);

//void add256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_add256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    add256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_add256_modm_obj, 2, 3, mod_trezorcrypto_monero_add256_modm);

//void sub256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_sub256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 3 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 3 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    sub256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_sub256_modm_obj, 2, 3, mod_trezorcrypto_monero_sub256_modm);

//void mulsub256_modm
STATIC mp_obj_t mod_trezorcrypto_monero_mulsub256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 4 ? 0 : -1;

    assert_scalar(res);
    assert_scalar(args[1+off]);
    assert_scalar(args[2+off]);
    assert_scalar(args[3+off]);
    mulsub256_modm(MP_OBJ_SCALAR(res), MP_OBJ_C_SCALAR(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_mulsub256_modm_obj, 3, 4, mod_trezorcrypto_monero_mulsub256_modm);

//void contract256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_pack256_modm(const mp_obj_t arg){
    assert_scalar(arg);
    uint8_t buff[32];
    contract256_modm(buff, MP_OBJ_C_SCALAR(arg));
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_pack256_modm_obj, mod_trezorcrypto_monero_pack256_modm);

//expand256_modm_r
STATIC mp_obj_t mod_trezorcrypto_monero_unpack256_modm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_scalar();
    const int off = n_args == 2 ? 0 : -1;
    assert_scalar(res);
    mp_unpack_scalar(MP_OBJ_SCALAR(res), args[1+off]);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_unpack256_modm_obj, 1, 2, mod_trezorcrypto_monero_unpack256_modm);

//
// GE25519 Defs
//

//void ge25519_set_neutral(ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_set_neutral(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 1 ? args[0] : mp_obj_new_ge25519();
    assert_ge25519(res);
    ge25519_set_neutral(&MP_OBJ_GE25519(res));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_set_neutral_obj, 0, 1, mod_trezorcrypto_monero_ge25519_set_neutral);

//void ge25519_set_xmr_h(ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_set_xmr_h(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 1 ? args[0] : mp_obj_new_ge25519();
    assert_ge25519(res);
    ge25519_set_xmr_h(&MP_OBJ_GE25519(res));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_set_xmr_h_obj, 0, 1, mod_trezorcrypto_monero_ge25519_set_xmr_h);

//int ge25519_check(const ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_check(const mp_obj_t arg){
  assert_ge25519(arg);
  if (ge25519_check(&MP_OBJ_C_GE25519(arg)) != 1){
    mp_raise_ValueError("Ed25519 point not on curve");
  }
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519_check_obj, mod_trezorcrypto_monero_ge25519_check);

//int ge25519_fromfe_check(const ge25519 *r);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_fromfe_check(const mp_obj_t arg){
  assert_ge25519(arg);
  if (ge25519_fromfe_check(&MP_OBJ_C_GE25519(arg)) != 1){
    mp_raise_ValueError("Invalid ed25519 point");
  }
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519_fromfe_check_obj, mod_trezorcrypto_monero_ge25519_fromfe_check);

//int ge25519_eq(const ge25519 *a, const ge25519 *b);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_eq(const mp_obj_t a, const mp_obj_t b){
    assert_ge25519(a);
    assert_ge25519(b);
    int r = ge25519_eq(&MP_OBJ_C_GE25519(a), &MP_OBJ_C_GE25519(b));
    return MP_OBJ_NEW_SMALL_INT(r);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_monero_ge25519_eq_obj, mod_trezorcrypto_monero_ge25519_eq);

//void ge25519_norm(ge25519 *r, const ge25519 *t);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_norm(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    mp_obj_t src = n_args == 2 ? args[1] : args[0];
    assert_ge25519(res);
    assert_ge25519(src);
    ge25519_norm(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(src));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_norm_obj, 1, 2, mod_trezorcrypto_monero_ge25519_norm);

//void ge25519_add(ge25519 *r, const ge25519 *a, const ge25519 *b, unsigned char signbit);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_add(size_t n_args, const mp_obj_t *args){
    mp_int_t s = 0;
    assert_ge25519(args[0]);
    assert_ge25519(args[1]);
    assert_ge25519(args[2]);
    if (n_args == 4){
        s = mp_obj_get_int(args[3]);
    }

    ge25519_add(&MP_OBJ_GE25519(args[0]), &MP_OBJ_C_GE25519(args[1]), &MP_OBJ_C_GE25519(args[2]), s);
    return args[0];
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_add_obj, 3, 4, mod_trezorcrypto_monero_ge25519_add);

//void ge25519_double(ge25519 *r, const ge25519 *p);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    mp_obj_t src = n_args == 2 ? args[1] : args[0];
    assert_ge25519(src);
    assert_ge25519(res);

    ge25519_double(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(src));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_obj, 1, 2, mod_trezorcrypto_monero_ge25519_double);

//void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 4 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 4 ? 0 : -1;

    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[2+off]);
    assert_scalar(args[3+off]);

    ge25519_double_scalarmult_vartime(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]),
                                      MP_OBJ_C_SCALAR(args[2+off]), MP_OBJ_C_SCALAR(args[3+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime_obj, 3, 4, mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime);

//void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 5 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 5 ? 0 : -1;

    assert_ge25519(res);
    assert_ge25519(args[1+off]);
    assert_scalar(args[2+off]);
    assert_ge25519(args[3+off]);
    assert_scalar(args[4+off]);

    ge25519_double_scalarmult_vartime2(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]),  MP_OBJ_C_SCALAR(args[2+off]),
                                       &MP_OBJ_C_GE25519(args[3+off]), MP_OBJ_C_SCALAR(args[4+off]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2_obj, 4, 5, mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2);

//void ge25519_scalarmult_base_wrapper(ge25519 *r, const bignum256modm s);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_scalarmult_base(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    assert_ge25519(res);
    if (MP_OBJ_IS_SCALAR(args[1+off])){
        ge25519_scalarmult_base_wrapper(&MP_OBJ_GE25519(res), MP_OBJ_C_SCALAR(args[1+off]));
    } else if (mp_obj_is_integer(args[1+off])){
        bignum256modm mlt;
        set256_modm(mlt, mp_obj_get_int(args[1+off]));
        ge25519_scalarmult_base_wrapper(&MP_OBJ_GE25519(res), mlt);
    } else {
        mp_raise_ValueError("unknown base mult type");
    }

    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_scalarmult_base_obj, 1, 2, mod_trezorcrypto_monero_ge25519_scalarmult_base);

//void ge25519_scalarmult_wrapper(ge25519 *r, const ge25519 *P, const bignum256modm a);
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_scalarmult(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    assert_ge25519(res);
    assert_ge25519(args[1+off]);

    if (MP_OBJ_IS_SCALAR(args[2+off])){
        ge25519_scalarmult_wrapper(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), MP_OBJ_C_SCALAR(args[2+off]));
    } else if (mp_obj_is_integer(args[2+off])){
        bignum256modm mlt;
        set256_modm(mlt, mp_obj_get_int(args[2+off]));
        ge25519_scalarmult_wrapper(&MP_OBJ_GE25519(res), &MP_OBJ_C_GE25519(args[1+off]), mlt);
    } else {
        mp_raise_ValueError("unknown mult type");
    }

    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_scalarmult_obj, 2, 3, mod_trezorcrypto_monero_ge25519_scalarmult);

//void ge25519_pack(unsigned char r[32], const ge25519 *p)
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_pack(const mp_obj_t arg){
    assert_ge25519(arg);
    uint8_t buff[32];
    ge25519_pack(buff, &MP_OBJ_C_GE25519(arg));

    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_monero_ge25519_pack_obj, mod_trezorcrypto_monero_ge25519_pack);

//int ge25519_unpack_vartime(ge25519 *r, const unsigned char *s)
STATIC mp_obj_t mod_trezorcrypto_monero_ge25519_unpack_vartime(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = n_args == 2 ? args[0] : mp_obj_new_ge25519();
    const int off = n_args == 2 ? 0 : -1;
    assert_ge25519(res);
    mp_unpack_ge25519(&MP_OBJ_GE25519(res), args[1+off]);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_monero_ge25519_unpack_vartime_obj, 1, 2, mod_trezorcrypto_monero_ge25519_unpack_vartime);

//
// XMR defs
//

/// def
STATIC mp_obj_t mod_trezorcrypto_monero_gen_range_proof(size_t n_args, const mp_obj_t *args) {
    uint64_t amount;
    xmr_range_sig_t rsig;
    ge25519 C;
    bignum256modm mask;

    const bignum256modm * last_mask = NULL;
    amount = mp_obj_get_uint64(args[0]);
    if (n_args > 1){
        last_mask = &MP_OBJ_C_SCALAR(args[1]);
    }

    xmr_gen_range_sig(&rsig, &C, mask, amount, last_mask);
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
    .make_new = mod_trezorcrypto_monero_ge25519_make_new,
    //.locals_dict = (void*)&mod_trezorcrypto_Sha512_locals_dict,
};

STATIC const mp_obj_type_t mod_trezorcrypto_monero_bignum256modm_type = {
    { &mp_type_type },
    .name = MP_QSTR_bignum256modm,
    .make_new = mod_trezorcrypto_monero_bignum256modm_make_new,
//    .locals_dict = (void*)&mod_trezorcrypto_Sha512_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_monero_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_monero) },
    { MP_ROM_QSTR(MP_QSTR_init256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_init256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_check256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_check256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_iszero256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_iszero256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_eq256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_eq256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_get256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_get256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_reduce256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_reduce256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_add256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_add256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_sub256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_sub256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_mulsub256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_mulsub256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_pack256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_pack256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_unpack256_modm), MP_ROM_PTR(&mod_trezorcrypto_monero_unpack256_modm_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_set_neutral), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_set_neutral_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_set_h), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_set_xmr_h_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_pack), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_pack_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_unpack_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_unpack_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_check), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_check_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_fromfe_check), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_fromfe_check_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_eq), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_eq_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_norm), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_norm_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_add), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double_scalarmult_vartime), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_double_scalarmult_vartime2), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_double_scalarmult_vartime2_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_scalarmult_base), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_scalarmult_base_obj) },
    { MP_ROM_QSTR(MP_QSTR_ge25519_scalarmult), MP_ROM_PTR(&mod_trezorcrypto_monero_ge25519_scalarmult_obj) },
    { MP_ROM_QSTR(MP_QSTR_gen_range_proof), MP_ROM_PTR(&mod_trezorcrypto_monero_gen_range_proof_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_monero_globals, mod_trezorcrypto_monero_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_monero_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_monero_globals,
};
