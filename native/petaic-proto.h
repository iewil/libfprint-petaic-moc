/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <gio/gio.h>

#define PT_SMALL_SIZE 128
#define PT_EXT_SIZE 2048
#define PT_EXT_OUT_PAYLOAD 2039
#define PT_EXT_IN_PAYLOAD 2038

guint16 pt_u16 (const guint8 *p);
guint32 pt_u32 (const guint8 *p);
guint64 pt_u64 (const guint8 *p);
void pt_put32 (guint8 *p, guint32 value);
gboolean pt_small_request (guint8 command, const guint8 *payload, gsize length,
                           guint8 packet[PT_SMALL_SIZE], GError **error);
gboolean pt_small_response (const guint8 *packet, gsize size, guint8 command,
                            guint8 *event, const guint8 **payload, gsize *length,
                            GError **error);
void pt_extended_request (guint8 command, const guint8 payload[PT_EXT_OUT_PAYLOAD],
                          guint8 packet[PT_EXT_SIZE]);
gboolean pt_extended_response (const guint8 *packet, gsize size, guint8 command,
                               const guint8 **payload, gsize *length, GError **error);
gboolean pt_database_size (const guint8 *payload, gsize length,
                           guint *count, GError **error);
gboolean pt_enrollment_commit_payload (const guint8 id[32], guint8 subfactor,
                                       guint8 payload[80], GError **error);
gboolean pt_enrollment_result (guint8 event, const guint8 *payload, gsize length,
                               guint *algorithm_result, guint *accepted_images,
                               guint *max_samples, gboolean *complete,
                               GError **error);
gboolean pt_enrollment_match_result (guint8 event, gsize length, GError **error);
extern const guint8 pt_database_header[36];
