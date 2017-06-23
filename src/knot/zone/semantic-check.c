/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dnssec/keytag.h"
#include "dnssec/nsec.h"
#include "dnssec/error.h"
#include "knot/zone/semantic-check.h"
#include "knot/common/log.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "contrib/base32hex.h"
#include "contrib/mempattern.h"
#include "contrib/wire.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/rrset-sign.h"

static const char *zonechecks_error_messages[(-ZC_ERR_UNKNOWN) + 1] = {
	[-ZC_ERR_UNKNOWN] =
	"unknown error",

	[-ZC_ERR_MISSING_SOA] =
	"missing SOA in zone apex",
	[-ZC_ERR_MISSING_NS_DEL_POINT] =
	"missing NS in zone apex",

	[-ZC_ERR_RRSIG_RDATA_TYPE_COVERED] =
	"wrong Type Covered in RRSIG",
	[-ZC_ERR_RRSIG_RDATA_TTL] =
	"wrong Original TTL in RRSIG",
	[-ZC_ERR_RRSIG_RDATA_EXPIRATION] =
	"expired RRSIG",
	[-ZC_ERR_RRSIG_RDATA_INCEPTION] =
	"RRSIG inception in the future",
	[-ZC_ERR_RRSIG_RDATA_LABELS] =
	"wrong Labels in RRSIG",
	[-ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER] =
	"wrong Signer's Name in RRSIG",
	[-ZC_ERR_RRSIG_NO_RRSIG] =
	"missing RRSIG",
	[-ZC_ERR_RRSIG_SIGNED] =
	"signed RRSIG",
	[-ZC_ERR_RRSIG_TTL] =
	"wrong RRSIG TTL",
	[-ZC_ERR_RRSIG_UNVERIFIABLE] =
	"unverifiable signature",
	[-ZC_ERR_RRSIG_OBSOLETE] =
	"obsolete signature - missing signed RRset",

	[-ZC_ERR_NO_NSEC] =
	"missing NSEC",
	[-ZC_ERR_NSEC_RDATA_BITMAP] =
	"incorrect type bitmap in NSEC",
	[-ZC_ERR_NSEC_RDATA_MULTIPLE] =
	"multiple NSEC records",
	[-ZC_ERR_NSEC_RDATA_CHAIN] =
	"incoherent NSEC chain",

	[-ZC_ERR_NSEC3_NOT_FOUND] =
	"missing NSEC3",
	[-ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT] =
	"insecure delegation outside NSEC3 opt-out",
	[-ZC_ERR_NSEC3_TTL] =
	"wrong Original TTL in NSEC3",
	[-ZC_ERR_NSEC3_RDATA_CHAIN] =
	"incoherent NSEC3 chain",
	[-ZC_ERR_NSEC3_EXTRA_RECORD] =
	"invalid record type in NSEC3 chain",
	[-ZC_ERR_NSEC3_RDATA_BITMAP] =
	"incorrect type bitmap in NSEC3",
	[-ZC_ERR_NSEC3_PARAM] =
	"incoherent NSEC3 parameters",
	[-ZC_ERR_NSEC3_PARAM_VALUE] =
	"incorrect NSEC3 parameter value",

	[-ZC_ERR_CNAME_EXTRA_RECORDS] =
	"other records exist at CNAME",
	[-ZC_ERR_DNAME_CHILDREN] =
	"child records exist under DNAME",
	[-ZC_ERR_CNAME_MULTIPLE] =
	"multiple CNAME records",
	[-ZC_ERR_DNAME_MULTIPLE] =
	"multiple DNAME records",
	[-ZC_ERR_CNAME_WILDCARD_SELF] =
	"loop in CNAME processing",
	[-ZC_ERR_DNAME_WILDCARD_SELF] =
	"loop in DNAME processing",

	[-ZC_ERR_GLUE_RECORD] =
	"missing glue record",

	[-ZC_ERR_BAD_DS] =
	"bad parameter value in DS",

	[-ZC_ERR_CDS_CDNSKEY] =
	"invalid CDS and CDNSKEY pair",

	[-ZC_ERR_INVALID_KEY] =
	"invalid dnssec key",
};


const char* semantic_check_error_msg(int ecode)
{
	if (ecode < ZC_ERR_UNKNOWN || ecode > ZC_ERR_LAST) {
		ecode = ZC_ERR_UNKNOWN;
	}
	if (zonechecks_error_messages[-ecode] == NULL) {
		ecode = ZC_ERR_UNKNOWN;
	}
	return zonechecks_error_messages[-ecode];
}

enum check_levels {
	MANDATORY = 1 << 0,
	OPTIONAL =  1 << 1,
	NSEC =      1 << 2,
	NSEC3 =     1 << 3,
};

typedef struct semchecks_data {
	zone_contents_t *zone;
	err_handler_t *handler;
	bool fatal_error;
	const zone_node_t *next_nsec;
	enum check_levels level;
	time_t context_time;
} semchecks_data_t;

static int check_cname_multiple(const zone_node_t *node, semchecks_data_t *data);
static int check_dname(const zone_node_t *node, semchecks_data_t *data);
static int check_delegation(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data);
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data);
static int check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data);
static int check_ds(const zone_node_t *node, semchecks_data_t *data);
static int check_submission_records(const zone_node_t *node, semchecks_data_t *data);

struct check_function {
	int (*function)(const zone_node_t *, semchecks_data_t *);
	enum check_levels level;
};

/* List of function callbacks for defined check_level */
static const struct check_function CHECK_FUNCTIONS[] = {
	{check_cname_multiple,    MANDATORY},
	{check_dname,             MANDATORY},
	{check_ds,		  MANDATORY},
	{check_delegation,        OPTIONAL},
	{check_submission_records,OPTIONAL},
	{check_rrsig,             NSEC | NSEC3},
	{check_signed_rrsig,      NSEC | NSEC3},
	{check_nsec,              NSEC},
	{check_nsec3,             NSEC3},
	{check_nsec3_presence,    NSEC3},
	{check_nsec3_opt_out,     NSEC3},
	{check_nsec_bitmap,       NSEC | NSEC3},
};

static const int CHECK_FUNCTIONS_LEN = sizeof(CHECK_FUNCTIONS)
                                     / sizeof(struct check_function);

static int dnssec_key_from_rdata(dnssec_key_t **key, const knot_dname_t *kown,
				 const uint8_t *rdata, size_t rdlen)
{
	if (!key || !rdata || rdlen == 0) {
		return KNOT_EINVAL;
	}

	dnssec_key_t *new_key = NULL;
	const dnssec_binary_t binary_key = {
		.size = rdlen,
		.data = (uint8_t *)rdata
	};

	int ret = dnssec_key_new(&new_key);
	if (ret != DNSSEC_EOK) {
		return KNOT_ENOMEM;
	}
	ret = dnssec_key_set_rdata(new_key, &binary_key);
	if (ret != DNSSEC_EOK) {
		dnssec_key_free(new_key);
		return KNOT_ENOMEM;
	}
	if (kown) {
		ret = dnssec_key_set_dname(new_key, kown);
		if (ret != DNSSEC_EOK) {
			dnssec_key_free(new_key);
			return KNOT_ENOMEM;
		}
	}

	*key = new_key;
	return KNOT_EOK;
}

static int check_signature(const knot_rdataset_t *rrsigs, size_t pos,
                       const dnssec_key_t *key, const knot_rrset_t *covered,
                       int trim_labels)
{
	if (!rrsigs || !key || !dnssec_key_can_verify(key)) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	dnssec_sign_ctx_t *sign_ctx = NULL;
	dnssec_binary_t signature = {0, };

	knot_rrsig_signature(rrsigs, pos, &signature.data, &signature.size);
	if (!signature.data || !signature.size) {
		ret = KNOT_EINVAL;
		goto fail;
	}

	if (dnssec_sign_new(&sign_ctx, key) != KNOT_EOK) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	const knot_rdata_t *rr_data = knot_rdataset_at(rrsigs, pos);
	uint8_t *rdata = knot_rdata_data(rr_data);

	if (knot_sign_ctx_add_data(sign_ctx, rdata, covered) != KNOT_EOK) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	if (dnssec_sign_verify(sign_ctx, &signature) != KNOT_EOK) {
		ret = KNOT_EINVAL;
		goto fail;
	}

fail:
	dnssec_sign_free(sign_ctx);
	return ret;
}

/*!
 * \brief Semantic check - RRSIG rdata.
 *
 * \param handler    Pointer on function to be called in case of negative check.
 * \param zone       The zone the rrset is in.
 * \param node       The node in the zone contents.
 * \param rrsig      RRSIG rdataset.
 * \param rr_pos     Position of the RRSIG rdata in question (in the rdataset).
 * \param rrset      RRSet signed by the RRSIG.
 * \param context    The time stamp we check the rrsig validity according to.
 * \param level      Level of the check.
 * \param verified   Out: the RRSIG has been verified to be signed by existing DNSKEY.
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_rdata(err_handler_t *handler,
                             const zone_contents_t *zone,
                             const zone_node_t *node,
                             const knot_rdataset_t *rrsig,
                             size_t rr_pos,
                             const knot_rrset_t *rrset,
                             time_t context,
                             enum check_levels level,
                             bool *verified)
{
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type '%s'", type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}

	ret = KNOT_EOK;

	if (knot_rrsig_type_covered(rrsig, 0) != rrset->type) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
				  info_str, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* label number at the 2nd index should be same as owner's */
	uint8_t labels_rdata = knot_rrsig_labels(rrsig, rr_pos);

	int tmp = knot_dname_labels(rrset->owner, NULL) - labels_rdata;

	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(rrset->owner)) {
			ret = handler->cb(handler, zone, node,
			                  ZC_ERR_RRSIG_RDATA_LABELS,
					  info_str, ZC_SEVERITY_ERROR);
		} else {
			if (abs(tmp) != 1) {
				ret = handler->cb(handler, zone, node,
				                  ZC_ERR_RRSIG_RDATA_LABELS,
						  info_str, ZC_SEVERITY_ERROR);
			}
		}

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* check original TTL */
	uint32_t original_ttl = knot_rrsig_original_ttl(rrsig, rr_pos);

	uint16_t rr_count = rrset->rrs.rr_count;
	for (uint16_t i = 0; i < rr_count; ++i) {
		if (original_ttl != knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, i))) {
			ret = handler->cb(handler, zone, node,
			                  ZC_ERR_RRSIG_RDATA_TTL,
					  info_str, ZC_SEVERITY_ERROR);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	/* Check for expired signature. */
	if (knot_rrsig_sig_expiration(rrsig, rr_pos) < context) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_EXPIRATION,
				  info_str, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Check inception */
	if (knot_rrsig_sig_inception(rrsig, rr_pos) > context) {
		ret = handler->cb(handler, zone, node,
				  ZC_ERR_RRSIG_RDATA_INCEPTION,
				  info_str, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Check signer name. */
	const knot_dname_t *signer = knot_rrsig_signer_name(rrsig, rr_pos);
	if (!knot_dname_is_equal(signer, zone->apex->owner)) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
				  info_str, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Verify with public key - only one RRSIG of covered record needed */
	if (level & OPTIONAL && !*verified) {
		const knot_rdataset_t *dnskeys = node_rdataset(zone->apex, KNOT_RRTYPE_DNSKEY);
		if (dnskeys == NULL) {
			return KNOT_EOK;
		}

		for (int i = 0; i < dnskeys->rr_count; i++) {
			uint16_t flags = knot_dnskey_flags(dnskeys, i);
			uint8_t proto = knot_dnskey_proto(dnskeys, i);
			/* RFC 4034 2.1.1 & 2.1.2 */
			if (flags & DNSKEY_FLAGS_ZSK && proto == 3) {
				knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, i);
				dnssec_key_t *key;

				ret = dnssec_key_from_rdata(&key, zone->apex->owner,
							    knot_rdata_data(dnskey),
							    knot_rdata_rdlen(dnskey));
				if (ret == KNOT_EOK) {
					ret = check_signature(rrsig, rr_pos, key, rrset, 0);
					dnssec_key_free(key);
					if (ret == KNOT_EOK) {
						*verified = true;
						return ret;
					}
				}
			}
		}
	}

	return KNOT_EOK;
}

static int check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	/* signed rrsig - nonsense */
	if (node_rrtype_is_signed(node, KNOT_RRTYPE_RRSIG)) {
		return data->handler->cb(data->handler, data->zone, node,
					 ZC_ERR_RRSIG_SIGNED, NULL, ZC_SEVERITY_ERROR);
	}
	return KNOT_EOK;
}
/*!
 * \brief Semantic check - RRSet's RRSIG.
 *
 * \param handler    Pointer on function to be called in case of negative check.
 * \param zone       The zone the rrset is in.
 * \param node       The node in the zone contents.
 * \param rrset      RRSet signed by the RRSIG.
 * \param context    The time stamp we check the rrsig validity according to.
 * \param level      Level of the check.
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_in_rrset(err_handler_t *handler,
                                const zone_contents_t *zone,
                                const zone_node_t *node,
                                const knot_rrset_t *rrset,
                                time_t context,
                                enum check_levels level)
{
	if (handler == NULL || node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type '%s'",
	                   type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}
	knot_rdataset_t rrsigs;
	knot_rdataset_init(&rrsigs);
	ret = knot_synth_rrsig(rrset->type,
	                           node_rdataset(node, KNOT_RRTYPE_RRSIG),
	                           &rrsigs, NULL);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		goto finish_rrsig_in_rrset;
	}

	if (ret == KNOT_ENOENT) {
		ret = handler->cb(handler, zone, node,
		                   ZC_ERR_RRSIG_NO_RRSIG,
				   info_str, ZC_SEVERITY_ERROR);
		goto finish_rrsig_in_rrset;
	}

	const knot_rdata_t *sig_rr = knot_rdataset_at(&rrsigs, 0);
	if (knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0)) != knot_rdata_ttl(sig_rr)) {
		ret = handler->cb(handler, zone, node, ZC_ERR_RRSIG_TTL, info_str, ZC_SEVERITY_ERROR);
		goto finish_rrsig_in_rrset;
	}

	bool verified = false;
	for (uint16_t i = 0; ret == KNOT_EOK && i < (&rrsigs)->rr_count; ++i) {
		ret = check_rrsig_rdata(handler, zone, node, &rrsigs, i, rrset,
		    context, level, &verified);
	}
	/* Only one rrsig of covered record needs to be verified by DNSKEY */
	if (!verified) {
		ret = handler->cb(handler, zone, node, ZC_ERR_RRSIG_UNVERIFIABLE,
				   info_str, ZC_SEVERITY_ERROR);
	}

finish_rrsig_in_rrset:
	knot_rdataset_clear(&rrsigs, NULL);
	return ret;
}

/*!
 * \brief Check if glue record for delegation is present.
 *
 * Also check if there is NS record in the zone.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_delegation(const zone_node_t *node, semchecks_data_t *data)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || data->zone->apex == node)) {
		return KNOT_EOK;
	}
	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
					 ZC_ERR_MISSING_NS_DEL_POINT, NULL,
					 ZC_SEVERITY_ERROR);
	}

	int ret = KNOT_EOK;

	// check glue record for delegation
	for (int i = 0; ret == KNOT_EOK && i < ns_rrs->rr_count; ++i) {
		const knot_dname_t *ns_dname = knot_ns_name(ns_rrs, i);
		if (!knot_dname_is_sub(ns_dname, node->owner)) {
			continue;
		}

		const zone_node_t *glue_node =
			zone_contents_find_node(data->zone, ns_dname);

		if (glue_node == NULL) {
			/* Try wildcard ([1]* + suffix). */
			knot_dname_t wildcard[KNOT_DNAME_MAXLEN];
			memcpy(wildcard, "\x1""*", 2);
			knot_dname_to_wire(wildcard + 2,
			                   knot_wire_next_label(ns_dname, NULL),
			                   sizeof(wildcard) - 2);
			glue_node = zone_contents_find_node(data->zone, wildcard);
		}
		if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
		    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
			ret = data->handler->cb(data->handler, data->zone,
						node, ZC_ERR_GLUE_RECORD, NULL, ZC_SEVERITY_ERROR);
		}
	}
	return ret;
}

/*!
 * \brief check_submission_records Check CDS and CDNSKEY
 */
static int check_submission_records(const zone_node_t *node, semchecks_data_t *data)
{
	int ret;
	const knot_rdataset_t *cdss = node_rdataset(node, KNOT_RRTYPE_CDS);
	const knot_rdataset_t *cdnskeys = node_rdataset(node, KNOT_RRTYPE_CDNSKEY);
	if (cdss == NULL && cdnskeys == NULL) {
		return KNOT_EOK;
	} else if (cdss == NULL || cdnskeys == NULL) {
		return data->handler->cb(data->handler, data->zone,
					 node, ZC_ERR_CDS_CDNSKEY,
					 NULL, ZC_SEVERITY_ERROR);
	}

	if (cdss->rr_count != 1 || cdnskeys->rr_count != 1) {
		ret = data->handler->cb(data->handler, data->zone,
					 node, ZC_ERR_CDS_CDNSKEY,
					 "more than one pair", ZC_SEVERITY_WARNING);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	knot_rdata_t *cdnskey = knot_rdataset_at(cdnskeys, 0);
	knot_rdata_t *cds = knot_rdataset_at(cdss, 0);
	uint8_t digest_type = knot_ds_digest_type(cdss, 0);

	const knot_rdataset_t *dnskeys = node_rdataset(data->zone->apex, KNOT_RRTYPE_DNSKEY);
	if (dnskeys == NULL) {
		return data->handler->cb(data->handler, data->zone,
					 node, ZC_ERR_CDS_CDNSKEY,
					"no dnskeys", ZC_SEVERITY_ERROR);
	}

	for (int i = 0; i < dnskeys->rr_count; i++) {
		knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, i);
		if (knot_rdata_cmp(dnskey, cdnskey) == 0) {
			dnssec_key_t *key;
			ret = dnssec_key_from_rdata(&key, data->zone->apex->owner,
							    knot_rdata_data(dnskey),
							    knot_rdata_rdlen(dnskey));
			if (ret != KNOT_EOK) {
				continue;
			}

			uint16_t flags = dnssec_key_get_flags(key);
			dnssec_binary_t cds_calc = { 0 };
			dnssec_binary_t cds_orig = { .size = knot_rdata_rdlen(cds),
						     .data = knot_rdata_data(cds) };
			ret = dnssec_key_create_ds(key, digest_type, &cds_calc);
			if (ret != KNOT_EOK) {
				continue;
			}
			ret = dnssec_binary_cmp(&cds_orig, &cds_calc);
			dnssec_binary_free(&cds_calc);
			dnssec_key_free(key);
			if (ret == 0) {
				if (!(flags & DNSKEY_FLAGS_KSK)) {
					return data->handler->cb(data->handler,
								 data->zone,
								 node,
								 ZC_ERR_CDS_CDNSKEY,
								 "not ksk",
								 ZC_SEVERITY_ERROR);
				} else {
					return KNOT_EOK;
				}
			} else {
				return data->handler->cb(data->handler, data->zone,
					node, ZC_ERR_CDS_CDNSKEY,
					"pair does not match", ZC_SEVERITY_ERROR);
			}
		}
	}

	return data->handler->cb(data->handler, data->zone,
				 node, ZC_ERR_CDS_CDNSKEY,
				 "corresponding dnskey missing", ZC_SEVERITY_ERROR);
}

/*!
 * \brief Semantic check - DS record.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 *
 * \retval KNOT_EOK on success.
 * \return Appropriate error code if error was found.
 */
static int check_ds(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dss = node_rdataset(node, KNOT_RRTYPE_DS);
	if (dss == NULL) {
	    return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	for (int i = 0; i < dss->rr_count; i++) {
		uint16_t keytag = knot_ds_key_tag(dss, i);
		uint8_t digest_type = knot_ds_digest_type(dss, i);

		char buffer[100] = { 0 };

		if (digest_type < 1 || digest_type > 4) {
			snprintf(buffer, 100, "type - keytag %d", keytag);
			ret = data->handler->cb(data->handler, data->zone,
						node, ZC_ERR_BAD_DS, buffer,
						ZC_SEVERITY_ERROR);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			uint8_t *digest;
			uint16_t digest_size;

			knot_ds_digest(dss, i, &digest, &digest_size);
			// sizes for different digest algorithms, 0 - invalid, ...
			const uint16_t digest_sizes [] = { 0xffff, 20, 32, 32, 48};

			if (digest_sizes[digest_type] != digest_size) {
				snprintf(buffer, 100, "hash length - keytag %d", keytag);
				ret = data->handler->cb(data->handler, data->zone,
						  node, ZC_ERR_BAD_DS, buffer, ZC_SEVERITY_ERROR);
				if (ret != KNOT_EOK) {
					return ret;
				}
			}
		}
	}

	return ret;
}

/*!
 * \brief Run all semantic check related to RRSIG record
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	bool deleg = node->flags & NODE_FLAGS_DELEG;

	int ret = KNOT_EOK;

	int rrset_count = node->rrset_count;
	for (int i = 0; ret == KNOT_EOK && i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if (deleg && rrset.type != KNOT_RRTYPE_NSEC &&
		    rrset.type != KNOT_RRTYPE_DS ) {
			continue;
		}

		ret = check_rrsig_in_rrset(data->handler, data->zone, node, &rrset,
					   data->context_time, data->level);
	}
	return ret;
}

/*!
 * \brief Add all RR types from a node into the bitmap.
 */
static void bitmap_add_all_node_rrsets(dnssec_nsec_bitmap_t *bitmap,
                                       const zone_node_t *node)
{
	bool deleg = node->flags & NODE_FLAGS_DELEG;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);
		if (deleg && (rr.type != KNOT_RRTYPE_NS &&
		              rr.type != KNOT_RRTYPE_DS &&
			      rr.type != KNOT_RRTYPE_NSEC &&
			      rr.type != KNOT_RRTYPE_RRSIG)) {
			continue;
		}
		dnssec_nsec_bitmap_add(bitmap, rr.type);
	}
}

/*!
 * \brief Check NSEC and NSEC3 type bitmap
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	knot_rdataset_t *nsec_rrs;

	if (data->level & NSEC) {
		nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	} else {
		if ( node->nsec3_node == NULL ) {
			return KNOT_EOK;
		}
		nsec_rrs = node_rdataset(node->nsec3_node, KNOT_RRTYPE_NSEC3);
	}
	if (nsec_rrs == NULL) {
		return KNOT_EOK;
	}

	// create NSEC bitmap from node
	dnssec_nsec_bitmap_t *node_bitmap = dnssec_nsec_bitmap_new();
	if (node_bitmap == NULL) {
		return KNOT_ENOMEM;
	}
	bitmap_add_all_node_rrsets(node_bitmap, node);

	uint16_t node_wire_size = dnssec_nsec_bitmap_size(node_bitmap);
	uint8_t *node_wire = malloc(node_wire_size);
	if (node_wire == NULL) {
		dnssec_nsec_bitmap_free(node_bitmap);
		return KNOT_ENOMEM;
	}
	dnssec_nsec_bitmap_write(node_bitmap, node_wire);

	// get NSEC bitmap from NSEC node
	uint8_t *nsec_wire = NULL;
	uint16_t nsec_wire_size = 0;
	if (data->level & NSEC) {
		knot_nsec_bitmap(nsec_rrs, &nsec_wire, &nsec_wire_size);
	} else {
		knot_nsec3_bitmap(nsec_rrs, 0, &nsec_wire, &nsec_wire_size);
	}

	int ret = KNOT_EOK;

	if (node_wire_size != nsec_wire_size ||
	    memcmp(node_wire, nsec_wire, node_wire_size) != 0) {
		if (data->level & NSEC) {
			ret = data->handler->cb(data->handler,
		                        data->zone, node,
					ZC_ERR_NSEC_RDATA_BITMAP,
					NULL, ZC_SEVERITY_ERROR);
		} else {
			char *owner = knot_dname_to_str_alloc(node->nsec3_node->owner);
			ret = data->handler->nsec3(data->handler, owner,
					data->zone, node,
					ZC_ERR_NSEC3_RDATA_BITMAP,
					NULL, ZC_SEVERITY_ERROR);
			free(owner);
		}
	}

	free(node_wire);
	dnssec_nsec_bitmap_free(node_bitmap);
	return ret;
}

/*!
 * \brief Run NSEC related semantic checks
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	if (node->rrset_count == 0) { // empty nonterminal
		return KNOT_EOK;
	}

	/* check for NSEC record */
	const knot_rdataset_t *nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	if (nsec_rrs == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
					 ZC_ERR_NO_NSEC, NULL, ZC_SEVERITY_ERROR);
	}

	int ret = KNOT_EOK;

	/* Test that only one record is in the NSEC RRSet */
	if (nsec_rrs->rr_count != 1) {
		ret = data->handler->cb(data->handler,
		                        data->zone, node,
		                        ZC_ERR_NSEC_RDATA_MULTIPLE,
					NULL, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (data->next_nsec != node) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC_RDATA_CHAIN,
					NULL, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/*
	 * Test that NSEC chain is coherent.
	 * We have already checked that every
	 * authoritative node contains NSEC record
	 * so checking should only be matter of testing
	 * the next link in each node.
	 */
	const knot_dname_t *next_domain = knot_nsec_next(nsec_rrs);

	data->next_nsec = zone_contents_find_node(data->zone, next_domain);

	if (data->next_nsec == NULL) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC_RDATA_CHAIN,
					NULL, ZC_SEVERITY_ERROR);
	}

	return ret;
}

/*!
 * \brief Check if node has NSEC3 node.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data)
{
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;

	if ((deleg && node_rrtype_exists(node, KNOT_RRTYPE_DS)) || (auth && !deleg)) {
		if(node->nsec3_node == NULL) {
			return data->handler->cb(data->handler, data->zone, node,
						 ZC_ERR_NSEC3_NOT_FOUND, NULL, ZC_SEVERITY_ERROR);
		}
	}
	return KNOT_EOK;
}

/*!
 * \brief Check NSEC3 opt out.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data)
{
	if (!(node->nsec3_node == NULL && node->flags & NODE_FLAGS_DELEG)) {
		return KNOT_EOK;
	}
	/* Insecure delegation, check whether it is part of opt-out span */

	const zone_node_t *nsec3_previous = NULL;
	const zone_node_t *nsec3_node;
	zone_contents_find_nsec3_for_name(data->zone, node->owner, &nsec3_node,
	                                  &nsec3_previous);

	if (nsec3_previous == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
					 ZC_ERR_NSEC3_NOT_FOUND, NULL, ZC_SEVERITY_ERROR);
	}

	const knot_rdataset_t *previous_rrs;
	previous_rrs = node_rdataset(nsec3_previous, KNOT_RRTYPE_NSEC3);

	assert(previous_rrs);

	/* check for Opt-Out flag */
	uint8_t flags = knot_nsec3_flags(previous_rrs, 0);
	uint8_t opt_out_mask = 1;

	if (!(flags & opt_out_mask)) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT,
					 NULL, ZC_SEVERITY_ERROR);
	}
	return KNOT_EOK;
}

/*!
 * \brief Run checks related to NSEC3.
 *
 * Check NSEC3 node for given node.
 * Check if NSEC3 chain is coherent and cyclic.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;
	char *hash_info = NULL;
	const zone_node_t *nsec3_node = node->nsec3_node;
	const knot_rdataset_t *nsec3_rrs = node_rdataset(nsec3_node,
						    KNOT_RRTYPE_NSEC3);

	int ret = KNOT_EOK;

	if (!auth && !deleg) {
		return KNOT_EOK;
	}
	if (node->nsec3_node == NULL) {
		return KNOT_EOK;
	}

	char *owner = knot_dname_to_str_alloc(nsec3_node->owner);
	if (nsec3_rrs == NULL) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
				     ZC_ERR_NSEC_RDATA_CHAIN, "invalid NSEC3 owner", ZC_SEVERITY_ERROR);
		goto nsec3_cleanup;
	}

	const knot_rdata_t *nsec3_rr = knot_rdataset_at(nsec3_rrs, 0);
	const knot_rdataset_t *soa_rrs = node_rdataset(data->zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs);
	uint32_t minimum_ttl = knot_soa_minimum(soa_rrs);
	if (knot_rdata_ttl(nsec3_rr) != minimum_ttl) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_TTL, NULL, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			goto nsec3_cleanup;
		}
	}

	// check parameters
	const knot_rdataset_t *nsec3param = node_rdataset(data->zone->apex,
							  KNOT_RRTYPE_NSEC3PARAM);
	dnssec_nsec3_params_t params_apex = { 0 };
	knot_rdata_t *rrd = knot_rdataset_at(nsec3param, 0);
	dnssec_binary_t rdata = { .size = knot_rdata_rdlen(rrd), .data = knot_rdata_data(rrd)};
	ret = dnssec_nsec3_params_from_rdata(&params_apex, &rdata);
	if (ret != DNSSEC_EOK) {
		goto nsec3_cleanup;
	}

	if (knot_nsec3_flags(nsec3_rrs, 0) > 1) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_PARAM_VALUE, "flags", ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			goto nsec3_cleanup;
		}
	}

	dnssec_binary_t salt = {
		.size = knot_nsec3_salt_length(nsec3_rrs, 0),
		.data = (uint8_t *)knot_nsec3_salt(nsec3_rrs, 0),
	};

	if (dnssec_binary_cmp(&salt, &params_apex.salt)) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_PARAM, "salt", ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			goto nsec3_cleanup;
		}
	}

	if (knot_nsec3_algorithm(nsec3_rrs, 0) != params_apex.algorithm) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_PARAM, "algorithm", ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			goto nsec3_cleanup;
		}
	}

	if (knot_nsec3_iterations(nsec3_rrs, 0) != params_apex.iterations) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_PARAM, "iterations", ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			goto nsec3_cleanup;
		}
	}

	/* Get next nsec3 node */
	/* Result is a dname, it can't be larger */
	const zone_node_t *apex = data->zone->apex;
	uint8_t *next_dname_str = NULL;
	uint8_t next_dname_size = 0;
	knot_nsec3_next_hashed(nsec3_rrs, 0, &next_dname_str,
	                           &next_dname_size);
	knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
	                                                    next_dname_size,
	                                                    apex->owner);

	if (next_dname == NULL) {
		ret = KNOT_ENOMEM;
		goto nsec3_cleanup;
	}

	uint8_t label[KNOT_DNAME_MAXLEN];
	int32_t label_size;
	label_size = base32hex_encode(next_dname_str, next_dname_size, label, sizeof(label));

	const zone_node_t *next_nsec3 =
		zone_contents_find_nsec3_node(data->zone, next_dname);
	hash_info = malloc(label_size + 1);
	snprintf(hash_info, label_size + 1, "%.*s", label_size, label);

	if (next_nsec3 == NULL) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_RDATA_CHAIN, hash_info, ZC_SEVERITY_ERROR);
	} else if (next_nsec3->prev != nsec3_node) {
		ret = data->handler->nsec3(data->handler, owner, data->zone, node,
					ZC_ERR_NSEC3_RDATA_CHAIN, hash_info, ZC_SEVERITY_ERROR);
	}

	/* Check that the node only contains NSEC3 and RRSIG. */
	for (int i = 0; ret == KNOT_EOK && i < nsec3_node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(nsec3_node, i);
		uint16_t type = rrset.type;
		if (!(type == KNOT_RRTYPE_NSEC3 || type == KNOT_RRTYPE_RRSIG)) {
			ret = data->handler->nsec3(data->handler, owner, data->zone, nsec3_node,
						ZC_ERR_NSEC3_EXTRA_RECORD, NULL, ZC_SEVERITY_ERROR);
		}
	}

nsec3_cleanup:
	dnssec_nsec3_params_free(&params_apex);
	knot_dname_free(&next_dname, NULL);
	free(hash_info);
	free(owner);
	return ret;
}

/*!
 * \brief Check if CNAME record contains other records
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_cname_multiple(const zone_node_t *node, semchecks_data_t *data)
{
	const  knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	int ret = KNOT_EOK;
	if (cname_rrs == NULL) {
		return KNOT_EOK;
	}

	unsigned rrset_limit = 1;
	/* With DNSSEC node can contain RRSIGs or NSEC */
	if (node_rrtype_exists(node, KNOT_RRTYPE_NSEC)) {
		rrset_limit += 1;
	}
	if (node_rrtype_exists(node, KNOT_RRTYPE_RRSIG)) {
		rrset_limit += 1;
	}

	if (node->rrset_count > rrset_limit) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
					ZC_ERR_CNAME_EXTRA_RECORDS, NULL, ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if (cname_rrs->rr_count != 1) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
					ZC_ERR_CNAME_MULTIPLE, NULL, ZC_SEVERITY_ERROR);
	}
	return ret;
}

/*!
 * \brief Check if DNAME record has children.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_dname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);
	int ret = KNOT_EOK;

	if (dname_rrs != NULL && node->children != 0) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_DNAME_CHILDREN,
					"records exist below the DNAME", ZC_SEVERITY_ERROR);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (node->parent != NULL && node_rrtype_exists(node->parent, KNOT_RRTYPE_DNAME)) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_DNAME_CHILDREN,
					"record is occluded by a parent DNAME", ZC_SEVERITY_ERROR);
	}
	return ret;
}

/*!
 * \brief Check that NSEC chain is cyclic.
 *
 * Run only once per zone. Check that last NSEC node points to first one.
 * \param data Semantic checks context data
 */
static int check_nsec_cyclic(semchecks_data_t *data)
{
	if (data->next_nsec == NULL) {
		return data->handler->cb(data->handler, data->zone,
		                         data->zone->apex,
					 ZC_ERR_NSEC_RDATA_CHAIN, NULL, ZC_SEVERITY_ERROR);
	}
	if (!knot_dname_is_equal(data->next_nsec->owner, data->zone->apex->owner)) {
		return data->handler->cb(data->handler, data->zone, data->next_nsec,
					 ZC_ERR_NSEC_RDATA_CHAIN, NULL, ZC_SEVERITY_ERROR);
	}
	return KNOT_EOK;
}

/*!
 * \brief Call all semantic checks for each node.
 *
 * This function is called as callback from zone_contents_tree_apply_inorder.
 * Checks are functions from global const array check_functions.
 *
 * \param node Node to be checked
 * \param data Semantic checks context data
 */
static int do_checks_in_tree(zone_node_t *node, void *data)
{
	struct semchecks_data *s_data = (semchecks_data_t *)data;

	int ret = KNOT_EOK;

	if (node->rrset_count == 1) {
		knot_rrset_t rrset = node_rrset_at(node, 0);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			return s_data->handler->cb(s_data->handler, s_data->zone, node,
						 ZC_ERR_RRSIG_OBSOLETE, NULL, ZC_SEVERITY_WARNING);
		}
	}

	for (int i = 0; ret == KNOT_EOK && i < CHECK_FUNCTIONS_LEN; ++i) {
		if (CHECK_FUNCTIONS[i].level & s_data->level) {
			ret = CHECK_FUNCTIONS[i].function(node, s_data);
		}
	}


	return ret;
}
#define NSEC3_PARAM_OPTOUT 1
static int check_nsec3param(knot_rdataset_t *nsec3param, zone_contents_t *zone,
			    err_handler_t *handler, semchecks_data_t *data)
{
	int ret = KNOT_EOK;
	if (nsec3param != NULL) {
		data->level |= NSEC3;
		uint8_t param = knot_nsec3param_flags(nsec3param, 0);
		if ((param & ~NSEC3_PARAM_OPTOUT) != 0) {
			ret = handler->cb(handler, zone, zone->apex,
					  ZC_ERR_NSEC3_PARAM_VALUE,
					  "NSEC3PARAM flags", ZC_SEVERITY_ERROR);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		param = knot_nsec3param_algorithm(nsec3param, 0);
		if (param != DNSSEC_NSEC3_ALGORITHM_SHA1) {
			ret = handler->cb(handler, zone, zone->apex,
					  ZC_ERR_NSEC3_PARAM_VALUE,
					  "NSEC3PARAM algorthm", ZC_SEVERITY_ERROR);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}
	return KNOT_EOK;
}

static int check_dnskey(zone_contents_t *zone, err_handler_t *handler) {
	const knot_rdataset_t *dnskeys = node_rdataset(zone->apex,
						       KNOT_RRTYPE_DNSKEY);
	int ret = KNOT_EOK;
	if (dnskeys != NULL) {
		for (int i = 0; i < dnskeys->rr_count; i++) {
			knot_rdata_t *dnskey = knot_rdataset_at(dnskeys, i);
			dnssec_key_t *key;
			ret = dnssec_key_from_rdata(&key, zone->apex->owner,
						    knot_rdata_data(dnskey),
						    knot_rdata_rdlen(dnskey));
			if (ret == KNOT_EOK) {
				dnssec_key_free(key);
			}
			//  RFC 4034: 2.1.2. The Protocol Field MUST have value 3
			if (knot_dnskey_proto(dnskeys, i) == 3 && ret == KNOT_EOK) {
				continue;
			}

			char buff[10];
			int r = snprintf(buff, 10, "%d.", i + 1);
			if (r < 0 || r >= 10) {
				return KNOT_ENOMEM;
			}

			ret = handler->cb(handler, zone, zone->apex,
					  ZC_ERR_INVALID_KEY, buff, ZC_SEVERITY_ERROR);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	} else {
		ret = handler->cb(handler, zone, zone->apex,
			  ZC_ERR_INVALID_KEY, "no key found", ZC_SEVERITY_ERROR);
	}
	return ret;
}

int zone_do_sem_checks(zone_contents_t *zone, bool optional,
		       err_handler_t *handler, time_t context)
{
	if (!zone || !handler) {
		return KNOT_EINVAL;
	}

	semchecks_data_t data = {
		.handler = handler,
		.zone = zone,
		.next_nsec = zone->apex,
		.fatal_error = false,
		.level = MANDATORY,
		.context_time = context,
		};
	int ret;
	if (optional) {
		data.level |= OPTIONAL;
		if (zone_contents_is_signed(zone)) {
			knot_rdataset_t *nsec3param = node_rdataset(zone->apex,
								    KNOT_RRTYPE_NSEC3PARAM);
			if (nsec3param != NULL) {
				data.level |= NSEC3;
				ret = check_nsec3param(nsec3param, zone, handler, &data);
				if (ret != KNOT_EOK) {
					return ret;
				}
			} else {
				data.level |= NSEC;
			}
			ret = check_dnskey(zone, handler);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	ret = zone_contents_apply(zone, do_checks_in_tree, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (data.fatal_error) {
		return KNOT_ESEMCHECK;
	}
	// check cyclic chain after every node was checked
	if (data.level & NSEC) {
		check_nsec_cyclic(&data);
	}

	if (data.fatal_error) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}
