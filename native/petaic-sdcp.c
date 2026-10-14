/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "petaic-sdcp.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

static gboolean
bad (GError **error, const gchar *message)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED, message);
  return FALSE;
}

gboolean
pt_mac (const guint8 key[32], const gchar *label, const guint8 *data,
        gsize length, guint8 out[32])
{
  gsize prefix = strlen (label) + 1;
  g_autofree guint8 *input = g_malloc (prefix + length);
  memcpy (input, label, prefix);
  if (length) memcpy (input + prefix, data, length);
  guint size = 0;
  return HMAC (EVP_sha256 (), key, 32, input, prefix + length, out, &size) && size == 32;
}

gboolean
pt_kdf (const guint8 key[32], const gchar *label, const guint8 *context,
        gsize context_length, guint8 *out, gsize out_length)
{
  if (!out_length || out_length > 4096) return FALSE;
  gsize label_length = strlen (label) + 1;
  gsize size = 4 + label_length + context_length + 4;
  g_autofree guint8 *input = g_malloc (size);
  memcpy (input + 4, label, label_length);
  if (context_length) memcpy (input + 4 + label_length, context, context_length);
  guint32 bits = GUINT32_TO_BE (out_length * 8);
  memcpy (input + size - 4, &bits, 4);
  for (gsize offset = 0, counter = 1; offset < out_length; offset += 32, counter++)
    {
      guint8 block[32]; guint written = 0;
      guint32 index = GUINT32_TO_BE (counter);
      memcpy (input, &index, 4);
      if (!HMAC (EVP_sha256 (), key, 32, input, size, block, &written) || written != 32)
        return FALSE;
      memcpy (out + offset, block, MIN ((gsize) 32, out_length - offset));
      OPENSSL_cleanse (block, sizeof block);
    }
  return TRUE;
}

void
pt_sdcp_clear (PtSdcp *session)
{
  EVP_PKEY_free (session->host_key);
  OPENSSL_cleanse (session, sizeof *session);
}

gboolean
pt_sdcp_begin (PtSdcp *session, GError **error)
{
  pt_sdcp_clear (session);
  session->host_key = EVP_PKEY_Q_keygen (NULL, NULL, "EC", "prime256v1");
  gsize size = sizeof session->host_public;
  if (!session->host_key || RAND_bytes (session->host_random, 32) != 1 ||
      !EVP_PKEY_get_octet_string_param (session->host_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        session->host_public, size, &size) || size != 65)
    return bad (error, "Cannot generate fresh SDCP host key/randomness");
  return TRUE;
}

static EVP_PKEY *
public_key (const guint8 bytes[65])
{
  EVP_PKEY *key = NULL;
  OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new ();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  OSSL_PARAM *params = NULL;
  if (bytes[0] != 4 || !builder || !ctx ||
      !OSSL_PARAM_BLD_push_utf8_string (builder, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_octet_string (builder, OSSL_PKEY_PARAM_PUB_KEY, bytes, 65)) goto done;
  params = OSSL_PARAM_BLD_to_param (builder);
  if (!params || EVP_PKEY_fromdata_init (ctx) != 1 ||
      EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1) goto done;
  EVP_PKEY_CTX *check = EVP_PKEY_CTX_new (key, NULL);
  if (!check || EVP_PKEY_public_check (check) != 1)
    { EVP_PKEY_free (key); key = NULL; }
  EVP_PKEY_CTX_free (check);
done:
  OSSL_PARAM_free (params); OSSL_PARAM_BLD_free (builder); EVP_PKEY_CTX_free (ctx);
  return key;
}

static gboolean
signature (EVP_PKEY *key, const guint8 *data, gsize size, const guint8 raw[64])
{
  gboolean result = FALSE;
  ECDSA_SIG *sig = ECDSA_SIG_new ();
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  BIGNUM *r = BN_bin2bn (raw, 32, NULL), *s = BN_bin2bn (raw + 32, 32, NULL);
  unsigned char *der = NULL;
  if (!key || !sig || !ctx || !r || !s) goto done;
  if (!ECDSA_SIG_set0 (sig, r, s)) goto done;
  r = s = NULL;
  int size_der = i2d_ECDSA_SIG (sig, &der);
  if (size_der <= 0 || EVP_DigestVerifyInit (ctx, NULL, EVP_sha256 (), NULL, key) != 1) goto done;
  result = EVP_DigestVerify (ctx, der, size_der, data, size) == 1;
done:
  BN_free (r); BN_free (s); OPENSSL_free (der); ECDSA_SIG_free (sig); EVP_MD_CTX_free (ctx);
  return result;
}

static X509 *
load_cert (const gchar *directory, const gchar *name, const gchar *expected)
{
  g_autofree gchar *path = g_build_filename (directory, name, NULL);
  g_autofree gchar *bytes = NULL;
  gsize length;
  if (!g_file_get_contents (path, &bytes, &length, NULL)) return NULL;
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256, (guint8 *) bytes, length);
  if (strcmp (digest, expected)) return NULL;
  const unsigned char *start = (guint8 *) bytes;
  X509 *cert = d2i_X509 (NULL, &start, length);
  if (start != (guint8 *) bytes + length) { X509_free (cert); return NULL; }
  return cert;
}

gboolean
pt_policy_check (PtSdcp *session, const gchar *path, gboolean development, gboolean *allow_expired,
        GError **error)
{
  /* Open an immutable snapshot, reject symlinks/writable policy before parsing. */
  int fd = open (path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (fd < 0) return bad (error, "Missing reader-and-firmware trust policy");
  if (fstat (fd, &st) || !S_ISREG (st.st_mode) || st.st_size <= 0 || st.st_size > 16384 ||
      (st.st_mode & 022) || st.st_uid != (development ? getuid () : 0))
    { close (fd); return bad (error, "Unsafe trust-policy ownership or permissions"); }
  gchar contents[16385]; gsize offset = 0;
  while (offset < (gsize) st.st_size)
    {
      ssize_t got = read (fd, contents + offset, st.st_size - offset);
      if (got <= 0) { close (fd); return bad (error, "Cannot read trust policy"); }
      offset += got;
    }
  close (fd);
  g_autoptr(GKeyFile) file = g_key_file_new ();
  if (!g_key_file_load_from_data (file, contents, offset, G_KEY_FILE_NONE, error)) return FALSE;
  const gchar *names[] = { "device-key-sha256", "firmware-sha256", "model-certificate-sha256" };
  const guint8 *values[] = { session->device_hash, session->firmware_hash, session->model_hash };
  for (guint i = 0; i < 3; i++)
    {
      g_autofree gchar *hex = g_key_file_get_string (file, "reader", names[i], NULL);
      if (!hex || strlen (hex) != 64) return bad (error, "Incomplete reader trust policy");
      for (guint j = 0; j < 32; j++)
        {
          int a = g_ascii_xdigit_value (hex[2 * j]), b = g_ascii_xdigit_value (hex[2 * j + 1]);
          if (a < 0 || b < 0 || ((a << 4) | b) != values[i][j])
            return bad (error, "Reader, firmware or model certificate differs from trusted pin");
        }
    }
  *allow_expired = g_key_file_get_boolean (file, "reader", "allow-expired-model", NULL);
  return TRUE;
}

gboolean
pt_sdcp_connect (PtSdcp *session, const guint8 *claim, gsize length,
                 const gchar *cert_dir, const gchar *policy_path, gboolean development,
                 GError **error)
{
  X509 *model = NULL, *root = NULL, *ca1 = NULL, *ca2 = NULL;
  X509_STORE *store = NULL; X509_STORE_CTX *verify = NULL;
  STACK_OF(X509) *intermediates = NULL;
  EVP_PKEY *model_key = NULL, *device_key = NULL, *firmware_key = NULL;
  EVP_PKEY_CTX *derive = NULL;
  gboolean ok = FALSE, allow_expired = FALSE;
  guint8 shared[32] = {0}, master[32] = {0}, keys[64] = {0}, mac[32], hash[32], context[64];
  if (!session->host_key || length < 1155 || length > PT_EXT_IN_PAYLOAD) goto done;
  for (gsize i = 1155; i < length; i++) if (claim[i]) goto done;
  SHA256 (claim + 865, 65, session->device_hash);
  memcpy (session->firmware_hash, claim + 995, 32);
  SHA256 (claim + 64, 801, session->model_hash);
  if (!pt_policy_check (session, policy_path, development, &allow_expired, error)) goto done;
  const unsigned char *der = claim + 64;
  model = d2i_X509 (NULL, &der, 801);
  if (!model || der != claim + 865) goto done;
  if (X509_check_ca (model) || !(X509_get_key_usage (model) & KU_DIGITAL_SIGNATURE)) goto done;
  root = load_cert (cert_dir, "root.der", "4c25971e3bdde59d178f7a5ef62561e9e88edd93c274ddaa522840cd4b4b517e");
  ca1 = load_cert (cert_dir, "gd-ca.der", "d06a3daedd39fc3050f30af50b4c923352cabb4f2ab81d833c999f63f5a7cbe0");
  ca2 = load_cert (cert_dir, "hello-pca.der", "dbfc7be1149785b5fd98a995b83184f51de39e9b277be287082f57514007c9c1");
  if (!root || !ca1 || !ca2) goto done;
  X509 *certs[] = { model, ca1, ca2, root };
  for (guint i = 0; i < 4; i++)
    {
      if (X509_cmp_current_time (X509_get0_notBefore (certs[i])) >= 0) goto done;
      int expiry = X509_cmp_current_time (X509_get0_notAfter (certs[i]));
      if (!expiry || (expiry < 0 && (i != 0 || !allow_expired))) goto done;
    }
  store = X509_STORE_new (); verify = X509_STORE_CTX_new (); intermediates = sk_X509_new_null ();
  if (!store || !verify || !intermediates || !X509_STORE_add_cert (store, root)) goto done;
  sk_X509_push (intermediates, ca1); sk_X509_push (intermediates, ca2);
  /* Time checked explicitly above: only the pinned leaf's expiry can be excepted. */
  X509_STORE_set_flags (store, X509_V_FLAG_NO_CHECK_TIME | X509_V_FLAG_CHECK_SS_SIGNATURE);
  if (!X509_STORE_CTX_init (verify, store, model, intermediates) || X509_verify_cert (verify) != 1) goto done;
  model_key = X509_get_pubkey (model);
  char group[80]; gsize group_length;
  if (!model_key || !EVP_PKEY_is_a (model_key, "EC") ||
      !EVP_PKEY_get_utf8_string_param (model_key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &group_length) ||
      strcmp (group, "prime256v1")) goto done;
  device_key = public_key (claim + 865); firmware_key = public_key (claim + 930);
  guint8 firmware_statement[99] = { 0xc0, 0x01 };
  memcpy (firmware_statement + 2, claim + 995, 32); memcpy (firmware_statement + 34, claim + 930, 65);
  if (!signature (model_key, claim + 865, 65, claim + 1027) ||
      !signature (device_key, firmware_statement, sizeof firmware_statement, claim + 1091)) goto done;
  derive = EVP_PKEY_CTX_new (session->host_key, NULL);
  gsize shared_length = 32;
  if (!derive || EVP_PKEY_derive_init (derive) != 1 ||
      EVP_PKEY_derive_set_peer (derive, firmware_key) != 1 ||
      EVP_PKEY_derive (derive, shared, &shared_length) != 1 || shared_length != 32) goto done;
  memcpy (context, session->host_random, 32); memcpy (context + 32, claim, 32);
  SHA256 (claim + 64, 1091, hash);
  if (!pt_kdf (shared, "master secret", context, 64, master, 32) ||
      !pt_kdf (master, "application keys", NULL, 0, keys, 64) ||
      !pt_mac (keys, "connect", hash, 32, mac) || CRYPTO_memcmp (mac, claim + 32, 32)) goto done;
  memcpy (session->secret, keys, 32); session->valid = TRUE; ok = TRUE;
done:
  X509_STORE_CTX_free (verify); X509_STORE_free (store); sk_X509_free (intermediates);
  X509_free (model); X509_free (root); X509_free (ca1); X509_free (ca2);
  EVP_PKEY_free (model_key); EVP_PKEY_free (device_key); EVP_PKEY_free (firmware_key); EVP_PKEY_CTX_free (derive);
  OPENSSL_cleanse (shared, sizeof shared); OPENSSL_cleanse (master, sizeof master); OPENSSL_cleanse (keys, sizeof keys);
  if (!ok) { session->valid = FALSE; OPENSSL_cleanse (session->secret, 32); if (!error || !*error) bad (error, "SDCP certificate, attestation or fresh claim validation failed"); }
  return ok;
}

gboolean
pt_sdcp_match (PtSdcp *session, const guint8 nonce[32], const guint8 *payload,
               gsize length, gboolean *matched, guint8 id[32], guint8 *subfactor, GError **error)
{
  if (!session->valid || length < 132 || length > PT_EXT_IN_PAYLOAD)
    return bad (error, "Invalid authenticated-match structure/session");
  guint32 decision = pt_u32 (payload + 36);
  *matched = FALSE;
  if (decision == 0) return TRUE;
  if (decision != 1 || pt_u32 (payload + 44) != 4)
    return bad (error, "Unexpected match decision or identity type");
  guint8 input[64], mac[32];
  memcpy (input, nonce, 32); memcpy (input + 32, payload + 48, 32);
  if (!pt_mac (session->secret, "identify", input, 64, mac) || CRYPTO_memcmp (mac, payload, 32))
    return bad (error, "Fresh authenticated match MAC mismatch");
  memcpy (id, payload + 48, 32); *subfactor = payload[120]; *matched = TRUE;
  return TRUE;
}

gboolean
pt_sdcp_enrollment_id (PtSdcp *session, const guint8 nonce[32], guint8 id[32], GError **error)
{
  if (!session || !session->valid || !nonce || !id)
    return bad (error, "Invalid SDCP enrollment-ID inputs/session");
  if (!pt_mac (session->secret, "enroll", nonce, 32, id))
    return bad (error, "Cannot derive SDCP enrollment identity");
  return TRUE;
}
