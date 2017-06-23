/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bignum.h"
#include "binary.h"
#include "error.h"
#include "key.h"
#include "key/algorithm.h"
#include "key/dnskey.h"
#include "shared.h"
#include "wire.h"

/* -- wrappers for GnuTLS types -------------------------------------------- */

static size_t bignum_size_u_datum(const gnutls_datum_t *_bignum)
{
	const dnssec_binary_t bignum = binary_from_datum(_bignum);
	return bignum_size_u(&bignum);
}

static void wire_write_bignum_datum(wire_ctx_t *ctx, size_t width,
				    const gnutls_datum_t *_bignum)
{
	const dnssec_binary_t bignum = binary_from_datum(_bignum);
	wire_write_bignum(ctx, width, &bignum);
}

static gnutls_datum_t wire_take_datum(wire_ctx_t *ctx, size_t count)
{
	gnutls_datum_t result = { .data = ctx->position, .size = count };
	ctx->position += count;

	return result;
}

/* -- DNSSEC to crypto ------------------------------------------------------*/

/*!
 * Convert RSA public key to DNSSEC format.
 */
static int rsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t modulus = { 0 };
	_cleanup_datum_ gnutls_datum_t exponent = { 0 };

	int result = gnutls_pubkey_get_pk_rsa_raw(key, &modulus, &exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t exponent_size = bignum_size_u_datum(&exponent);
	if (exponent_size > UINT8_MAX) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t modulus_size = bignum_size_u_datum(&modulus);

	result = dnssec_binary_alloc(rdata, 1 + exponent_size + modulus_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_write_u8(&wire, exponent_size);
	wire_write_bignum_datum(&wire, exponent_size, &exponent);
	wire_write_bignum_datum(&wire, modulus_size, &modulus);
	assert(wire_tell(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Convert DSA public key to DNSSEC format.
 */
static int dsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t p = { 0 };
	_cleanup_datum_ gnutls_datum_t q = { 0 };
	_cleanup_datum_ gnutls_datum_t g = { 0 };
	_cleanup_datum_ gnutls_datum_t y = { 0 };

	int result = gnutls_pubkey_get_pk_dsa_raw(key, &p, &q, &g, &y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t p_size = bignum_size_u_datum(&p);
	size_t q_size = bignum_size_u_datum(&q);
	size_t g_size = bignum_size_u_datum(&g);
	size_t y_size = bignum_size_u_datum(&y);

	if (q_size != 20) {
		// only certain key size range can be exported in DNSKEY
		return DNSSEC_INVALID_KEY_SIZE;
	}

	if (p_size != g_size || g_size != y_size) {
		return DNSSEC_INVALID_KEY_SIZE;
	}

	if (p_size < 64 || (p_size - 64) % 8 != 0) {
		return DNSSEC_INVALID_KEY_SIZE;
	}

	uint8_t t = (p_size - 64) / 8;

	size_t size = 1 + q_size + p_size + g_size + y_size;
	result = dnssec_binary_alloc(rdata, size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t ctx = wire_init_binary(rdata);
	wire_write_u8(&ctx, t);
	wire_write_bignum_datum(&ctx, q_size, &q);
	wire_write_bignum_datum(&ctx, p_size, &p);
	wire_write_bignum_datum(&ctx, g_size, &g);
	wire_write_bignum_datum(&ctx, y_size, &y);
	assert(wire_tell(&ctx) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Get point size for an ECDSA curve.
 */
static size_t ecdsa_curve_point_size(gnutls_ecc_curve_t curve)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_SECP256R1: return 32;
	case GNUTLS_ECC_CURVE_SECP384R1: return 48;
	default: return 0;
	}
}

/*!
 * Convert ECDSA public key to DNSSEC format.
 */
static int ecdsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	_cleanup_datum_ gnutls_datum_t point_y = { 0 };
	gnutls_ecc_curve_t curve = { 0 };

	int result = gnutls_pubkey_get_pk_ecc_raw(key, &curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t point_size = ecdsa_curve_point_size(curve);
	if (point_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	result = dnssec_binary_alloc(rdata, 2 * point_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_write_bignum_datum(&wire, point_size, &point_x);
	wire_write_bignum_datum(&wire, point_size, &point_y);
	assert(wire_tell(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/*!
 * Get point size for an EDDSA curve.
 */
static size_t eddsa_curve_point_size(gnutls_ecc_curve_t curve)
{
	switch (curve) {
	case GNUTLS_ECC_CURVE_ED25519: return 32;
	default: return 0;
	}
}

/*!
 * Convert EDDSA public key to DNSSEC format.
 */
static int eddsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	_cleanup_datum_ gnutls_datum_t point_x = { 0 };
	_cleanup_datum_ gnutls_datum_t point_y = { 0 };
	gnutls_ecc_curve_t curve = { 0 };

	int result = gnutls_pubkey_get_pk_ecc_raw(key, &curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	size_t point_size = eddsa_curve_point_size(curve);
	if (point_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	result = dnssec_binary_alloc(rdata, 2 * point_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(rdata);
	wire_write_bignum_datum(&wire, point_size, &point_x);
	wire_write_bignum_datum(&wire, point_size, &point_y);
	assert(wire_tell(&wire) == rdata->size);

	return DNSSEC_EOK;
}

/* -- crypto to DNSSEC ------------------------------------------------------*/

/*!
 * Convert RSA key in DNSSEC format to crypto key.
 */
static int rsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	if (rdata->size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx = wire_init_binary(rdata);

	// parse public exponent

	uint8_t exponent_size = wire_read_u8(&ctx);
	if (exponent_size == 0 || wire_available(&ctx) < exponent_size) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	gnutls_datum_t exponent = wire_take_datum(&ctx, exponent_size);

	// parse modulus

	size_t modulus_size = wire_available(&ctx);
	if (modulus_size == 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	gnutls_datum_t modulus = wire_take_datum(&ctx, modulus_size);

	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_rsa_raw(key, &modulus, &exponent);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/*!
 * Check if the size of DSA public key in DNSSEC format is correct.
 */
static bool valid_dsa_rdata_size(size_t size)
{
	// minimal key size
	if (size < 1 + 20 + 3 * 64) {
		return false;
	}

	// p, g, and y size equals
	size_t pgy_size = size - 20 - 1;
	if (pgy_size % 3 != 0) {
		return false;
	}

	// p size constraints
	size_t p_size = pgy_size / 3;
	if (p_size % 8 != 0) {
		return false;
	}

	return true;
}

/*!
 * Compute the DSA t value from RDATA public key size.
 */
static uint8_t expected_t_size(size_t size)
{
	size_t p_size = (size - 1 - 20) / 3;
	return (p_size - 64) / 8;
}

/*!
 * Convert DSA key in DNSSEC format to crypto key.
 */
static int dsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	if (!valid_dsa_rdata_size(rdata->size)) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	wire_ctx_t ctx = wire_init_binary(rdata);

	// read t

	uint8_t t = wire_read_u8(&ctx);
	if (t != expected_t_size(rdata->size)) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	// parse q

	gnutls_datum_t q = wire_take_datum(&ctx, 20);

	// parse p, g, and y

	size_t param_size = wire_available(&ctx) / 3;
	gnutls_datum_t p = wire_take_datum(&ctx, param_size);
	gnutls_datum_t g = wire_take_datum(&ctx, param_size);
	gnutls_datum_t y = wire_take_datum(&ctx, param_size);

	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_dsa_raw(key, &p, &q, &g, &y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/**
 * Get ECDSA curve based on DNSKEY RDATA size.
 */
static gnutls_ecc_curve_t ecdsa_curve_from_rdata_size(size_t rdata_size)
{
	switch (rdata_size) {
	case 64: return GNUTLS_ECC_CURVE_SECP256R1;
	case 96: return GNUTLS_ECC_CURVE_SECP384R1;
	default: return GNUTLS_ECC_CURVE_INVALID;
	}
}

/*!
 * Convert ECDSA key in DNSSEC format to crypto key.
 */
static int ecdsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_ecc_curve_t curve = ecdsa_curve_from_rdata_size(rdata->size);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	// parse points

	wire_ctx_t ctx = wire_init_binary(rdata);

	size_t point_size = wire_available(&ctx) / 2;
	gnutls_datum_t point_x = wire_take_datum(&ctx, point_size);
	gnutls_datum_t point_y = wire_take_datum(&ctx, point_size);
	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_ecc_raw(key, curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/*!
 * Convert EDDSA key in DNSSEC format to crypto key.
 */
static int eddsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_ecc_curve_t curve = ecdsa_curve_from_rdata_size(rdata->size);
	if (curve == GNUTLS_ECC_CURVE_INVALID) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	// parse points

	wire_ctx_t ctx = wire_init_binary(rdata);

	size_t point_size = wire_available(&ctx) / 2;
	gnutls_datum_t point_x = wire_take_datum(&ctx, point_size);
	gnutls_datum_t point_y = wire_take_datum(&ctx, point_size);
	assert(wire_tell(&ctx) == rdata->size);

	int result = gnutls_pubkey_import_ecc_raw(key, curve, &point_x, &point_y);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	return DNSSEC_EOK;
}

/* -- internal API --------------------------------------------------------- */

/*!
 * Encode public key to the format used in DNSKEY RDATA.
 */
int convert_pubkey_to_dnskey(gnutls_pubkey_t key, dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	int algorithm = gnutls_pubkey_get_pk_algorithm(key, NULL);
	if (algorithm < 0) {
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	switch ((gnutls_pk_algorithm_t)algorithm) {
	case GNUTLS_PK_RSA:           return rsa_pubkey_to_rdata(key, rdata);
	case GNUTLS_PK_DSA:           return dsa_pubkey_to_rdata(key, rdata);
	case GNUTLS_PK_EC:            return ecdsa_pubkey_to_rdata(key, rdata);
	case GNUTLS_PK_EDDSA_ED25519: return eddsa_pubkey_to_rdata(key, rdata);
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}

/*!
 * Create public key from the format encoded in DNSKEY RDATA.
 */
int convert_dnskey_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata,
			     gnutls_pubkey_t key)
{
	assert(rdata);
	assert(key);

	gnutls_pk_algorithm_t gnutls_alg = algorithm_to_gnutls(algorithm);

	switch(gnutls_alg) {
	case GNUTLS_PK_RSA:           return rsa_rdata_to_pubkey(rdata, key);
	case GNUTLS_PK_DSA:           return dsa_rdata_to_pubkey(rdata, key);
	case GNUTLS_PK_EC:            return ecdsa_rdata_to_pubkey(rdata, key);
	case GNUTLS_PK_EDDSA_ED25519: return eddsa_rdata_to_pubkey(rdata, key);
	default:
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}
}
