/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "petaic-proto.h"
#include <openssl/evp.h>

typedef struct {
  EVP_PKEY *host_key;
  guint8 host_random[32], host_public[65];
  guint8 secret[32], device_hash[32], firmware_hash[32], model_hash[32];
  gboolean valid;
} PtSdcp;

gboolean pt_sdcp_begin (PtSdcp *session, GError **error);
void pt_sdcp_clear (PtSdcp *session);
gboolean pt_sdcp_connect (PtSdcp *session, const guint8 *claim, gsize length,
                          const gchar *cert_dir, const gchar *policy_path,
                          gboolean development, GError **error);
gboolean pt_sdcp_match (PtSdcp *session, const guint8 nonce[32],
                        const guint8 *payload, gsize length, gboolean *matched,
                        guint8 id[32], guint8 *subfactor, GError **error);
gboolean pt_sdcp_enrollment_id (PtSdcp *session, const guint8 nonce[32],
                                guint8 id[32], GError **error);
gboolean pt_kdf (const guint8 key[32], const gchar *label, const guint8 *context,
                 gsize context_length, guint8 *out, gsize out_length);
gboolean pt_mac (const guint8 key[32], const gchar *label, const guint8 *data,
                 gsize length, guint8 out[32]);
gboolean pt_policy_check (PtSdcp *session, const gchar *path, gboolean development,
                          gboolean *allow_expired, GError **error);
