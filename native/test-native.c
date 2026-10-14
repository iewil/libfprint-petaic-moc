/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "petaic-sdcp.h"
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void framing (void)
{
  guint8 packet[128], event; const guint8 *payload; gsize length;
  g_autoptr(GError) error = NULL;
  g_assert_true (pt_small_request (0x10, NULL, 0, packet, &error));
  packet[0] = 4; packet[3] = 5; packet[4] = 1; packet[5] = 0x28;
  guint sum = 0; for (guint i = 0; i < 126; i++) sum += packet[i];
  packet[126] = sum; packet[127] = sum >> 8;
  g_assert_true (pt_small_response (packet, 128, 0x10, &event, &payload, &length, &error));
  g_assert_cmpuint (event, ==, 1); g_assert_cmpuint (length, ==, 4);
  packet[125] ^= 1;
  g_assert_false (pt_small_response (packet, 128, 0x10, &event, &payload, &length, &error));
  g_clear_error (&error);
  g_assert_false (pt_small_request (0xdf, NULL, 0, packet, &error));
  g_clear_error (&error);
  const guint8 enrollment_commands[] = { 0x13, 0x31, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6 };
  for (guint i = 0; i < G_N_ELEMENTS (enrollment_commands); i++)
    g_assert_true (pt_small_request (enrollment_commands[i], NULL, 0, packet, &error));
  guint8 mode = 2;
  g_assert_true (pt_small_request (0x13, &mode, 1, packet, &error));
  g_assert_cmpuint (packet[6], ==, 2);
  guint8 dump[PT_EXT_OUT_PAYLOAD], extended_packet[PT_EXT_SIZE];
  memset (dump, 1, sizeof dump);
  pt_extended_request (0x13, dump, extended_packet);
  for (guint i = 9; i < PT_EXT_SIZE; i++) g_assert_cmpuint (extended_packet[i], ==, 1);
  guint32 checksum = 0;
  for (guint i = 4; i < PT_EXT_SIZE; i++) checksum += extended_packet[i];
  g_assert_cmpuint (pt_u32 (extended_packet), ==, checksum);
  g_assert_false (pt_small_request (0xd7, NULL, 0, packet, &error));
}

static void match_auth (void)
{
  PtSdcp session = { .valid = TRUE };
  guint8 nonce[32], packet[132] = {0}, input[64], id[32], subfactor;
  for (guint i = 0; i < 32; i++) { session.secret[i] = i; nonce[i] = i + 32; packet[48 + i] = i + 64; }
  pt_put32 (packet + 36, 1); pt_put32 (packet + 44, 4); packet[120] = 0xf5;
  memcpy (input, nonce, 32); memcpy (input + 32, packet + 48, 32);
  g_assert_true (pt_mac (session.secret, "identify", input, 64, packet));
  gboolean matched;
  g_autoptr(GError) error = NULL;
  g_assert_true (pt_sdcp_match (&session, nonce, packet, sizeof packet, &matched, id, &subfactor, &error));
  g_assert_true (matched); g_assert_cmpuint (subfactor, ==, 0xf5);
  nonce[0] ^= 1;
  g_assert_false (pt_sdcp_match (&session, nonce, packet, sizeof packet, &matched, id, &subfactor, &error));
  g_assert_false (matched); g_clear_error (&error);
  pt_put32 (packet + 36, 0);
  g_assert_true (pt_sdcp_match (&session, nonce, packet, sizeof packet, &matched, id, &subfactor, &error));
  g_assert_false (matched);
}

static void kdf_vector (void)
{
  guint8 key[32], output[32]; for (guint i = 0; i < 32; i++) key[i] = i;
  /* Independent Python/public-spec counter-KDF value. */
  g_assert_true (pt_kdf (key, "master secret", NULL, 0, output, sizeof output));
  g_autofree gchar *hex = g_malloc0 (65);
  for (guint i = 0; i < 32; i++) g_snprintf (hex + 2 * i, 3, "%02x", output[i]);
  g_assert_cmpstr (hex, ==, "ce35e41ef84cb2db5ed72e40d3a3963d8afa8e3260d4cdd965dc1f793fca8592");
}

static void enrollment_primitives (void)
{
  PtSdcp session = { .valid = TRUE };
  guint8 nonce[32], id[32], expected[32], commit[80] = {0};
  for (guint i = 0; i < 32; i++) { session.secret[i] = i; nonce[i] = 31 - i; }
  g_autoptr(GError) error = NULL;
  g_assert_true (pt_mac (session.secret, "enroll", nonce, sizeof nonce, expected));
  g_assert_true (pt_sdcp_enrollment_id (&session, nonce, id, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (id, sizeof id, expected, sizeof expected);
  g_assert_true (pt_enrollment_commit_payload (id, 0xf6, commit, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (pt_u32 (commit), ==, 4);
  g_assert_cmpmem (commit + 4, 32, id, 32);
  g_assert_cmpuint (commit[76], ==, 0xf6);
  for (guint i = 36; i < 76; i++) g_assert_cmpuint (commit[i], ==, 0);
  for (guint i = 77; i < 80; i++) g_assert_cmpuint (commit[i], ==, 0);

  guint result, accepted, maximum; gboolean complete;
  guint8 reply[12] = {0}; reply[4] = 12; reply[7] = 12; reply[9] = 2;
  g_assert_true (pt_enrollment_result (0xa7, reply, sizeof reply, &result,
                                      &accepted, &maximum, &complete, &error));
  g_assert_no_error (error); g_assert_true (complete);
  g_assert_cmpuint (accepted, ==, 12); g_assert_cmpuint (maximum, ==, 12);
  g_assert_false (pt_enrollment_result (0x01, reply, sizeof reply, &result,
                                       &accepted, &maximum, &complete, &error));
  g_clear_error (&error);
  reply[7] = 5;
  g_assert_true (pt_enrollment_result (0xa6, reply, sizeof reply, &result,
                                       &accepted, &maximum, &complete, &error));
  g_assert_no_error (error); g_assert_false (complete); g_assert_cmpuint (accepted, ==, 5);
  reply[0] = 3;
  g_assert_true (pt_enrollment_result (0xa0, reply, sizeof reply, &result,
                                       &accepted, &maximum, &complete, &error));
  g_assert_no_error (error); g_assert_false (complete); g_assert_cmpuint (result, ==, 3);
  reply[0] = 0;
  reply[7] = 11;
  g_assert_false (pt_enrollment_result (0xa7, reply, sizeof reply, &result,
                                       &accepted, &maximum, &complete, &error));
  g_clear_error (&error);

  g_assert_true (pt_enrollment_match_result (0xaf, 120, &error));
  g_assert_no_error (error);
  g_assert_true (pt_enrollment_match_result (0x01, 120, &error));
  g_assert_no_error (error);
  g_assert_false (pt_enrollment_match_result (0x01, 0, &error));
  g_clear_error (&error);
  g_assert_false (pt_enrollment_match_result (0xaf, 119, &error));
  g_clear_error (&error);
}

static void policy_pins (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *path = NULL;
  int fd = g_file_open_tmp ("petaic-policy-XXXXXX", &path, &error);
  g_assert_cmpint (fd, >=, 0); close (fd);
  const gchar *zeros = "0000000000000000000000000000000000000000000000000000000000000000";
  g_autofree gchar *data = g_strdup_printf ("[reader]\ndevice-key-sha256=%s\nfirmware-sha256=%s\nmodel-certificate-sha256=%s\nallow-expired-model=true\n", zeros, zeros, zeros);
  g_assert_true (g_file_set_contents (path, data, -1, &error));
  g_assert_cmpint (chmod (path, 0600), ==, 0);
  PtSdcp session = {0}; gboolean expired = FALSE;
  gboolean accepted = pt_policy_check (&session, path, TRUE, &expired, &error);
  g_assert_no_error (error);
  g_assert_true (accepted);
  g_assert_true (expired);
  guint8 *pins[] = { session.device_hash, session.firmware_hash, session.model_hash };
  for (guint i = 0; i < 3; i++)
    {
      pins[i][0] = 1;
      g_assert_false (pt_policy_check (&session, path, TRUE, &expired, &error));
      g_assert_nonnull (strstr (error->message, "differs"));
      g_clear_error (&error); pins[i][0] = 0;
    }
  chmod (path, 0666);
  g_assert_false (pt_policy_check (&session, path, TRUE, &expired, &error));
  g_clear_error (&error); chmod (path, 0600);
  g_autofree gchar *link = g_strconcat (path, ".link", NULL);
  g_assert_cmpint (symlink (path, link), ==, 0);
  g_assert_false (pt_policy_check (&session, link, TRUE, &expired, &error));
  g_clear_error (&error);
  if (getuid () != 0)
    {
      g_assert_false (pt_policy_check (&session, path, FALSE, &expired, &error));
      g_clear_error (&error);
    }
  unlink (link); unlink (path);
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/petaic/framing", framing);
  g_test_add_func ("/petaic/fresh-match", match_auth);
  g_test_add_func ("/petaic/kdf", kdf_vector);
  g_test_add_func ("/petaic/enrollment-primitives", enrollment_primitives);
  g_test_add_func ("/petaic/trust-policy-pins", policy_pins);
  return g_test_run ();
}
