/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "petaic-proto.h"
#include <string.h>

/* c164704a-0c67-46c6-b087-b104e4f63c59, Windows GUID layout. Never create it. */
const guint8 pt_database_header[36] = {
  0x4a, 0x70, 0x64, 0xc1, 0x67, 0x0c, 0xc6, 0x46,
  0xb0, 0x87, 0xb1, 0x04, 0xe4, 0xf6, 0x3c, 0x59
};

guint16 pt_u16 (const guint8 *p) { return p[0] | ((guint16) p[1] << 8); }
guint32 pt_u32 (const guint8 *p) { return pt_u16 (p) | ((guint32) pt_u16 (p + 2) << 16); }
guint64 pt_u64 (const guint8 *p) { return pt_u32 (p) | ((guint64) pt_u32 (p + 4) << 32); }
void pt_put32 (guint8 *p, guint32 v)
{
  for (guint i = 0; i < 4; i++) p[i] = v >> (8 * i);
}

static guint32
sum (const guint8 *p, gsize size)
{
  guint32 result = 0;
  for (gsize i = 0; i < size; i++) result += p[i];
  return result;
}

static gboolean
bad (GError **error, const gchar *message)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, message);
  return FALSE;
}

gboolean
pt_small_request (guint8 command, const guint8 *payload, gsize length,
                  guint8 packet[PT_SMALL_SIZE], GError **error)
{
  /* Writes are enabled only for the capture-validated enrollment transaction. */
  switch (command)
    {
    case 0x0c: case 0x10: case 0x11: case 0x30: case 0x77:
    case 0x13: case 0x31: case 0xc0: case 0xc1: case 0xc2: case 0xc3:
    case 0xc4: case 0xc5: case 0xc6: case 0xc7: case 0xd5: case 0xd9:
    case 0xdb: break;
    default: return bad (error, "Command outside native allowlist");
    }
  if (length > 120 || (length && !payload)) return bad (error, "Invalid request length");
  memset (packet, 0, PT_SMALL_SIZE);
  packet[0] = length; packet[1] = length >> 8; packet[2] = command;
  if (length) memcpy (packet + 6, payload, length);
  guint16 checksum = sum (packet, 126);
  packet[126] = checksum; packet[127] = checksum >> 8;
  return TRUE;
}

gboolean
pt_small_response (const guint8 *packet, gsize size, guint8 command,
                   guint8 *event, const guint8 **payload, gsize *length, GError **error)
{
  if (size != PT_SMALL_SIZE || pt_u16 (packet + 126) != (sum (packet, 126) & 0xffff))
    return bad (error, "Small response length/checksum mismatch");
  if (packet[2] != command || packet[3] != 5 || pt_u16 (packet) > 120)
    return bad (error, "Small response command/marker/capacity mismatch");
  *event = packet[4]; /* Byte 5 is pre_ret_code, never a current decision. */
  *length = pt_u16 (packet); *payload = packet + 6;
  return TRUE;
}

void
pt_extended_request (guint8 command, const guint8 payload[PT_EXT_OUT_PAYLOAD],
                     guint8 packet[PT_EXT_SIZE])
{
  memset (packet, 0, PT_EXT_SIZE);
  pt_put32 (packet + 4, PT_EXT_OUT_PAYLOAD);
  packet[8] = command;
  memcpy (packet + 9, payload, PT_EXT_OUT_PAYLOAD);
  pt_put32 (packet, sum (packet + 4, PT_EXT_SIZE - 4));
}

gboolean
pt_extended_response (const guint8 *packet, gsize size, guint8 command,
                      const guint8 **payload, gsize *length, GError **error)
{
  if (size != PT_EXT_SIZE || pt_u32 (packet) != sum (packet + 4, PT_EXT_SIZE - 4))
    return bad (error, "Extended response length/checksum mismatch");
  if (packet[8] != command || packet[9] != 1 || pt_u32 (packet + 4) > PT_EXT_IN_PAYLOAD)
    return bad (error, "Extended response command/event/capacity mismatch");
  *payload = packet + 10; *length = pt_u32 (packet + 4);
  return TRUE;
}

gboolean
pt_database_size (const guint8 *payload, gsize length, guint *count, GError **error)
{
  if (length != 24 || pt_u32 (payload + 16) || pt_u32 (payload + 20))
    return bad (error, "Invalid database-size response");
  guint64 available = pt_u64 (payload), records = pt_u64 (payload + 8);
  if (available > 256 || records > 256 || available + records > 256)
    return bad (error, "Database capacity exceeds index range");
  *count = records;
  return TRUE;
}

gboolean
pt_enrollment_commit_payload (const guint8 id[32], guint8 subfactor,
                              guint8 payload[80], GError **error)
{
  gboolean nonzero = FALSE;
  if (!id || !payload || !subfactor)
    return bad (error, "Invalid enrollment commit inputs");
  for (guint i = 0; i < 32; i++) nonzero |= id[i] != 0;
  if (!nonzero) return bad (error, "Refusing an empty enrollment identity");
  memset (payload, 0, 80);
  pt_put32 (payload, 4); /* WINBIO_IDENTITY_TYPE_SECURE */
  memcpy (payload + 4, id, 32);
  payload[76] = subfactor;
  return TRUE;
}

gboolean
pt_enrollment_result (guint8 event, const guint8 *payload, gsize length,
                      guint *algorithm_result, guint *accepted_images,
                      guint *max_samples, gboolean *complete, GError **error)
{
  if (!payload || length != 12 || !algorithm_result || !accepted_images ||
      !max_samples || !complete)
    return bad (error, "Invalid enrollment result structure");
  if (event != 0xa0 && event != 0xa6 && event != 0xa7)
    return bad (error, "Unexpected enrollment result event");
  if (payload[10] || payload[11])
    return bad (error, "Unexpected enrollment result reserved bytes");
  *algorithm_result = pt_u32 (payload);
  *max_samples = pt_u16 (payload + 4);
  *accepted_images = payload[7];
  *complete = event == 0xa7;
  if (!*max_samples || *accepted_images > *max_samples ||
      (*complete && *accepted_images != *max_samples))
    return bad (error, "Inconsistent enrollment sample counts");
  return TRUE;
}

gboolean
pt_enrollment_match_result (guint8 event, gsize length, GError **error)
{
  /* Captures show 0xaf; this reader has returned generic OK (0x01) with the
   * same complete 120-byte result. Never accept either status without it. */
  if ((event != 0xaf && event != 0x01) || length != 120)
    return bad (error, "Invalid enrollment matching-result response");
  return TRUE;
}
