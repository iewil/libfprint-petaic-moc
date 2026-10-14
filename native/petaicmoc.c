/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native enrollment and authenticated matching backend for the PetaIC reader.
 */
#define FP_COMPONENT "petaicmoc"
#include "drivers_api.h"
#include "petaic-proto.h"
#include "petaic-sdcp.h"
#include <petaic-build-config.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>

#ifndef PETAIC_CERT_DIR
#define PETAIC_CERT_DIR "/etc/libfprint/petaicmoc"
#endif
#ifndef PETAIC_POLICY_PATH
#define PETAIC_POLICY_PATH "/etc/libfprint/petaicmoc/policy.ini"
#endif
#ifndef PETAIC_DEVELOPMENT_BUILD
#define PETAIC_DEVELOPMENT_BUILD 0
#endif

typedef struct _FpiDevicePetaicmoc FpiDevicePetaicmoc;
typedef void (*PtCallback) (FpiDevicePetaicmoc *, const guint8 *, gsize, GError *);
typedef void (*DumpDone) (FpiDevicePetaicmoc *, GError *);
typedef enum { IO_SETUP, IO_WRITE, IO_READ } IoStage;
typedef struct { guint8 id[32], subfactor; } Record;

struct _FpiDevicePetaicmoc {
  FpDevice parent;
  PtSdcp session;
  gboolean claimed, setup_done, inflight, extended, cancelled;
  gboolean preparing_action, need_release;
  gboolean enrollment_created, preflight_enrollment, commit_record_found, commit_sent;
  gboolean verifying_commit;
  DumpDone dump_done;
  guint retries;
  guint8 command, event, response_event, enrollment_event;
  IoStage io_stage;
  PtCallback callback;
  guint8 outgoing[PT_EXT_SIZE], incoming[PT_EXT_SIZE], nonce[32];
  gsize offset, frame_size;
  gint64 deadline;
  GCancellable *read_cancel;
  GError *operation_error;
  FpPrint *scan;
  gboolean matched;
  guint count, record_index;
  guint free_slots, accepted_images, max_samples;
  guint8 enrollment_id[32], enrollment_subfactor;
  Record records[256];
};
typedef FpDeviceClass FpiDevicePetaicmocClass;
GType fpi_device_petaicmoc_get_type (void);
G_DEFINE_TYPE (FpiDevicePetaicmoc, fpi_device_petaicmoc, FP_TYPE_DEVICE)
#define PT_SELF(dev) ((FpiDevicePetaicmoc *) (dev))

static const FpIdEntry id_table[] = { { .vid = 0x28e9, .pid = 0x5159 }, { .vid = 0, .pid = 0 } };
static void io_write (FpiDevicePetaicmoc *self);
static void io_read (FpiDevicePetaicmoc *self);
static void poll_finger (FpDevice *device, gpointer unused);
static void finish_action (FpiDevicePetaicmoc *self, GError *error);
static void prepare_connection (FpiDevicePetaicmoc *self);
static void start_enrollment (FpiDevicePetaicmoc *self);
static void enrollment_fail (FpiDevicePetaicmoc *self, GError *error);
static void enrollment_capture_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static void enrollment_poll (FpiDevicePetaicmoc *self);
static void dump_data (FpiDevicePetaicmoc *self, guint8 mode, DumpDone done);
static void preflight_dump_done (FpiDevicePetaicmoc *self, GError *error);
static void enrollment_apply_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static void enrollment_commit_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static void enrollment_created_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static void enrollment_commit_readback_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static void enrollment_post_commit_dump_done (FpiDevicePetaicmoc *self, GError *error);
static void preflight_time_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);
static GVariant *print_data (FpiDevicePetaicmoc *self, const guint8 id[32], guint8 subfactor);
static void match_ack_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error);

static void
connection_ready (FpiDevicePetaicmoc *self)
{
  if (self->preparing_action && fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL)
    {
      if (!self->free_slots)
        { finish_action (self, fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL)); return; }
      self->preflight_enrollment = TRUE;
      poll_finger (FP_DEVICE (self), NULL);
    }
  else if (self->preparing_action) poll_finger (FP_DEVICE (self), NULL);
  else fpi_device_open_complete (FP_DEVICE (self), NULL);
}

static GError *
proto_error (const gchar *message)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", message);
}

static void
transaction_done (FpiDevicePetaicmoc *self, GError *error)
{
  const guint8 *payload = NULL; gsize length = 0; guint8 event;
  PtCallback callback = self->callback;
  if (!error)
    {
      if (self->extended)
        pt_extended_response (self->incoming, self->offset, self->command, &payload, &length, &error);
      else if (pt_small_response (self->incoming, self->offset, self->command, &event, &payload, &length, &error))
        {
          self->response_event = event;
          if (self->command == 0xc5 && self->event == 0xff)
            {
              if (event != 0xa0 && event != 0xa6 && event != 0xa7)
                error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Unexpected enrollment event 0x%02x", event);
            }
          else if (self->command == 0xc1 && self->event == 0xaf)
            {
              if (!pt_enrollment_match_result (event, length, NULL))
                error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                   "Invalid enrollment matching result: event 0x%02x, %zu payload bytes",
                                                   event, length);
            }
          else if (self->command == 0xc4 && event == 0xa0)
            {
              /* A capture can be rejected before the apply-image command. Treat
               * this firmware response like the later c5 quality-retry event. */
              error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                                "Reader rejected this capture; lift and reposition your finger");
            }
          else if (event != self->event)
            {
              if (self->command == 0xc0 && event == 0xa0) error = fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
              else error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                      "Command 0x%02x returned event 0x%02x with %zu payload bytes",
                                                      self->command, event, length);
            }
          else if (self->command == 0x0c) self->setup_done = FALSE;
        }
    }
  self->inflight = FALSE;
  g_clear_object (&self->read_cancel);
  callback (self, payload, length, error);
}

static void
transfer_cb (FpiUsbTransfer *transfer, FpDevice *device, gpointer unused, GError *error)
{
  FpiDevicePetaicmoc *self = PT_SELF (device);
  if (error)
    {
      g_debug ("USB command 0x%02x failed at stage %u: %s", self->command,
               self->io_stage, error->message);
      transaction_done (self, error);
      return;
    }
  if (self->io_stage == IO_SETUP)
    {
      if (transfer->actual_length != 1 || transfer->buffer[0] != 0x5c)
        { transaction_done (self, proto_error ("Unexpected USB setup response")); return; }
      self->setup_done = TRUE;
      io_write (self);
    }
  else if (self->io_stage == IO_WRITE)
    {
      if (transfer->actual_length != (gssize) self->frame_size)
        { transaction_done (self, proto_error ("Partial USB request write; reconnect reader")); return; }
      self->deadline = g_get_monotonic_time () + ((self->command == 0xc0) ? 15000000 : 3000000);
      io_read (self);
    }
  else
    {
      if (transfer->actual_length <= 0 || transfer->actual_length > (gssize) (self->frame_size - self->offset))
        { transaction_done (self, proto_error ("Empty/oversized USB response")); return; }
      memcpy (self->incoming + self->offset, transfer->buffer, transfer->actual_length);
      self->offset += transfer->actual_length;
      if (self->offset < self->frame_size) io_read (self);
      else transaction_done (self, NULL);
    }
}

static void
io_write (FpiDevicePetaicmoc *self)
{
  self->io_stage = IO_WRITE;
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, 0x01, self->frame_size);
  memcpy (transfer->buffer, self->outgoing, self->frame_size);
  fpi_usb_transfer_submit (transfer, 3000, NULL, transfer_cb, NULL);
}

static void
io_read (FpiDevicePetaicmoc *self)
{
  self->io_stage = IO_READ;
  gint64 remaining = (self->deadline - g_get_monotonic_time () + 999) / 1000;
  if (remaining <= 0)
    { transaction_done (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "USB response deadline exceeded")); return; }
  if ((self->command == 0xc0 || self->command == 0xc4) && !self->extended && !self->read_cancel)
    {
      self->read_cancel = g_cancellable_new ();
      if (self->cancelled) g_cancellable_cancel (self->read_cancel);
    }
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, 0x81, self->frame_size - self->offset);
  fpi_usb_transfer_submit (transfer, remaining, self->read_cancel, transfer_cb, NULL);
}

static void
small (FpiDevicePetaicmoc *self, guint8 command, const guint8 *payload, gsize length,
       guint8 expected_event, PtCallback callback)
{
  g_assert (!self->inflight);
  GError *error = NULL;
  if (!pt_small_request (command, payload, length, self->outgoing, &error))
    { callback (self, NULL, 0, error); return; }
  self->command = command; self->event = expected_event; self->extended = FALSE;
  g_debug ("Sending small USB command 0x%02x", command);
  self->frame_size = PT_SMALL_SIZE; self->offset = 0; self->callback = callback; self->inflight = TRUE;
  if (self->setup_done) io_write (self);
  else
    {
      self->io_stage = IO_SETUP;
      FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));
      fpi_usb_transfer_fill_control (transfer, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                     G_USB_DEVICE_REQUEST_TYPE_VENDOR, G_USB_DEVICE_RECIPIENT_DEVICE,
                                     0xc0, 0, 0, 1);
      fpi_usb_transfer_submit (transfer, 1500, NULL, transfer_cb, NULL);
    }
}

static void
extended (FpiDevicePetaicmoc *self, guint8 command, const guint8 *payload, PtCallback callback)
{
  g_assert (!self->inflight);
  pt_extended_request (command, payload, self->outgoing);
  self->command = command; self->extended = TRUE; self->frame_size = PT_EXT_SIZE;
  g_debug ("Sending extended USB command 0x%02x", command);
  self->offset = 0; self->callback = callback; self->inflight = TRUE;
  io_write (self);
}

static void
open_fail (FpiDevicePetaicmoc *self, GError *error)
{
  if (self->preparing_action)
    { pt_sdcp_clear (&self->session); finish_action (self, error); return; }
  if (self->claimed)
    g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, NULL);
  self->claimed = self->setup_done = FALSE;
  pt_sdcp_clear (&self->session);
  fpi_device_open_complete (FP_DEVICE (self), error);
}

static void
record_fail (FpiDevicePetaicmoc *self, GError *error)
{
  if (self->verifying_commit)
    { self->verifying_commit = FALSE; enrollment_fail (self, error); }
  else open_fail (self, error);
}

static void
record_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (error)
    {
      record_fail (self, error);
      return;
    }
  if (length != 84 || pt_u32 (payload + 4) != 4)
    { record_fail (self, proto_error ("Unexpected secure-record format")); return; }
  for (guint i = 40; i < 84; i++)
    if (i != 80 && payload[i])
      { record_fail (self, proto_error ("Unexpected secure-record padding")); return; }
  gboolean nonzero = FALSE;
  for (guint i = 0; i < 32; i++) nonzero |= payload[8 + i] != 0;
  if (!nonzero) { record_fail (self, proto_error ("Empty secure identity")); return; }
  memcpy (self->records[self->record_index].id, payload + 8, 32);
  self->records[self->record_index].subfactor = payload[80];
  if (self->verifying_commit && self->records[self->record_index].subfactor == self->enrollment_subfactor &&
      !CRYPTO_memcmp (self->records[self->record_index].id, self->enrollment_id, 32))
    self->commit_record_found = TRUE;
  self->record_index++;
  if (self->record_index < self->count)
    {
      guint8 index = self->record_index;
      small (self, 0xd9, &index, 1, 1, record_cb);
    }
  else if (self->verifying_commit)
    {
      self->verifying_commit = FALSE;
      if (self->commit_record_found)
        {
          FpPrint *template = NULL;
          fpi_device_get_enroll_data (FP_DEVICE (self), &template);
          fpi_print_set_type (template, FPI_PRINT_RAW);
          fpi_print_set_device_stored (template, FALSE);
          /* g_object_set() sinks floating GVariants here; keep the expression
           * inline so an autoptr does not unref the value stored on FpPrint. */
          g_object_set (template, "fpi-data",
                        print_data (self, self->enrollment_id, self->enrollment_subfactor), NULL);
          fpi_device_enroll_progress (FP_DEVICE (self), self->max_samples, NULL, NULL);
          fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (template), NULL);
          self->preparing_action = FALSE;
          self->enrollment_created = FALSE;
          g_clear_error (&self->operation_error);
          OPENSSL_cleanse (self->enrollment_id, sizeof self->enrollment_id);
          OPENSSL_cleanse (self->nonce, sizeof self->nonce);
        }
      else
        {
          GError *failure = g_steal_pointer (&self->operation_error);
          if (!failure) failure = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "Commit was not present in reader storage; do not retry blindly");
          finish_action (self, failure);
        }
    }
  else connection_ready (self);
}

static void
size_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error) pt_database_size (payload, length, &self->count, &error);
  if (error) { open_fail (self, error); return; }
  self->record_index = 0;
  self->free_slots = pt_u64 (payload);
  if (!self->count)
    {
      if (self->preparing_action && fpi_device_get_current_action (FP_DEVICE (self)) != FPI_DEVICE_ACTION_ENROLL)
        finish_action (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND, "No enrolled prints on reader"));
      else connection_ready (self);
      return;
    }
  guint8 index = 0;
  small (self, 0xd9, &index, 1, 1, record_cb);
}

static void
database_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length) error = proto_error ("Unexpected database-open payload");
  if (error) { open_fail (self, error); return; }
  small (self, 0xd5, NULL, 0, 1, size_cb);
}

static void
connect_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error) pt_sdcp_connect (&self->session, payload, length, PETAIC_CERT_DIR,
                               PETAIC_POLICY_PATH, PETAIC_DEVELOPMENT_BUILD, &error);
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  OPENSSL_cleanse (self->outgoing, sizeof self->outgoing);
  if (error) { open_fail (self, error); return; }
  small (self, 0xdb, pt_database_header, sizeof pt_database_header, 0x27, database_cb);
}

static void
connect_ack_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (error) { open_fail (self, error); return; }
  guint8 input[PT_EXT_OUT_PAYLOAD] = {0};
  memcpy (input, self->session.host_random, 32); memcpy (input + 128, self->session.host_public, 65);
  extended (self, 0x77, input, connect_cb);
}

static gboolean
layout_valid (GUsbDevice *usb, GError **error)
{
  if (g_usb_device_get_release (usb) != 0x0100 || g_usb_device_get_device_class (usb) != 0xff ||
      g_usb_device_get_configuration (usb, error) != 1) return FALSE;
  g_autoptr(GPtrArray) interfaces = g_usb_device_get_interfaces (usb, error);
  if (!interfaces || interfaces->len != 1) return FALSE;
  GUsbInterface *interface = g_ptr_array_index (interfaces, 0);
  if (g_usb_interface_get_number (interface) || g_usb_interface_get_alternate (interface) ||
      g_usb_interface_get_class (interface) != 0xff) return FALSE;
  g_autoptr(GPtrArray) endpoints = g_usb_interface_get_endpoints (interface);
  if (!endpoints || endpoints->len != 2) return FALSE;
  guint bits = 0;
  for (guint i = 0; i < endpoints->len; i++)
    {
      GUsbEndpoint *ep = g_ptr_array_index (endpoints, i);
      /* GUsb "kind" is bDescriptorType, not bmAttributes. */
      if (g_usb_endpoint_get_kind (ep) != 5 || g_usb_endpoint_get_maximum_packet_size (ep) != 64) return FALSE;
      if (g_usb_endpoint_get_address (ep) == 0x01) bits |= 1;
      else if (g_usb_endpoint_get_address (ep) == 0x81) bits |= 2;
    }
  if (bits != 3) return FALSE;
  /* GUsb 0.4.8 does not expose bmAttributes: verify the raw descriptor too. */
  guint8 descriptor[32]; gsize actual = 0;
  if (!g_usb_device_control_transfer (usb, G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
      G_USB_DEVICE_REQUEST_TYPE_STANDARD, G_USB_DEVICE_RECIPIENT_DEVICE, 6, 0x0200, 0,
      descriptor, sizeof descriptor, &actual, 1500, NULL, error)) return FALSE;
  if (actual != sizeof descriptor || descriptor[0] != 9 || descriptor[1] != 2 ||
      pt_u16 (descriptor + 2) != 32 || descriptor[4] != 1 || descriptor[5] != 1 ||
      descriptor[9] != 9 || descriptor[10] != 4 || descriptor[11] || descriptor[12] ||
      descriptor[13] != 2 || descriptor[14] != 0xff) return FALSE;
  bits = 0;
  for (guint offset = 18; offset <= 25; offset += 7)
    {
      if (descriptor[offset] != 7 || descriptor[offset + 1] != 5 ||
          (descriptor[offset + 3] & 3) != 2 || pt_u16 (descriptor + offset + 4) != 64) return FALSE;
      if (descriptor[offset + 2] == 1) bits |= 1;
      else if (descriptor[offset + 2] == 0x81) bits |= 2;
    }
  return bits == 3;
}

static void
prepare_connection (FpiDevicePetaicmoc *self)
{
  GError *error = NULL;
  if (!pt_sdcp_begin (&self->session, &error)) { open_fail (self, error); return; }
  guint8 setup[16] = {0}; pt_put32 (setup, 2048); setup[4] = 0x11;
  small (self, 0x77, setup, sizeof setup, 1, connect_ack_cb);
}

static void
pt_open (FpDevice *device)
{
  FpiDevicePetaicmoc *self = PT_SELF (device); GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  if (!layout_valid (usb, &error))
    { if (!error) error = proto_error ("Reader USB personality does not match verified layout"); open_fail (self, error); return; }
  if (!g_usb_device_claim_interface (usb, 0, 0, &error)) { open_fail (self, error); return; }
  self->claimed = TRUE; self->setup_done = self->cancelled = FALSE;
  self->preparing_action = FALSE;
  prepare_connection (self);
}

static void
close_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  GError *release_error = NULL;
  if (!error && length) error = proto_error ("Unexpected cancel response payload");
  if (self->claimed && !g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)), 0, 0, &release_error))
    { if (!error) error = release_error; else g_clear_error (&release_error); }
  self->claimed = self->setup_done = FALSE;
  pt_sdcp_clear (&self->session); OPENSSL_cleanse (self->records, sizeof self->records);
  fpi_device_close_complete (FP_DEVICE (self), error);
}

static void pt_close (FpDevice *device)
{
  FpiDevicePetaicmoc *self = PT_SELF (device);
  if (self->setup_done) small (self, 0x0c, NULL, 0, 1, close_cb);
  else close_cb (self, NULL, 0, NULL);
}

static GVariant *
print_data (FpiDevicePetaicmoc *self, const guint8 id[32], guint8 subfactor)
{
  return g_variant_new ("(u@ay@ay@ayy)", 1,
      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, self->session.device_hash, 32, 1),
      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, self->session.firmware_hash, 32, 1),
      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, id, 32, 1), subfactor);
}

static FpPrint *
scan_print (FpiDevicePetaicmoc *self, const guint8 id[32], guint8 subfactor)
{
  FpPrint *print = fp_print_new (FP_DEVICE (self));
  fpi_print_set_type (print, FPI_PRINT_RAW);
  /* This host-side record authorizes one reader-resident secure identity. */
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", print_data (self, id, subfactor), NULL);
  return print;
}

static void
debug_print_comparison (FpPrint *wanted, FpPrint *scan)
{
  g_autoptr(GVariant) wanted_data = NULL;
  g_autoptr(GVariant) scan_data = NULL;
  gboolean fields_equal[5] = { FALSE };

  g_object_get (wanted, "fpi-data", &wanted_data, NULL);
  g_object_get (scan, "fpi-data", &scan_data, NULL);
  if (wanted_data && scan_data &&
      g_variant_is_of_type (wanted_data, G_VARIANT_TYPE ("(uayayayy)")) &&
      g_variant_is_of_type (scan_data, G_VARIANT_TYPE ("(uayayayy)")))
    for (guint i = 0; i < G_N_ELEMENTS (fields_equal); i++)
      {
        g_autoptr(GVariant) wanted_field = g_variant_get_child_value (wanted_data, i);
        g_autoptr(GVariant) scan_field = g_variant_get_child_value (scan_data, i);
        fields_equal[i] = g_variant_equal (wanted_field, scan_field);
      }
  fp_dbg ("Stored-print comparison: equal=%s version=%s reader=%s firmware=%s identity=%s subfactor=%s",
          fp_print_equal (wanted, scan) ? "yes" : "no",
          fields_equal[0] ? "same" : "different",
          fields_equal[1] ? "same" : "different",
          fields_equal[2] ? "same" : "different",
          fields_equal[3] ? "same" : "different",
          fields_equal[4] ? "same" : "different");
}

static void
finish_action (FpiDevicePetaicmoc *self, GError *error)
{
  FpDevice *device = FP_DEVICE (self);
  FpiDeviceAction action = fpi_device_get_current_action (device);
  FpPrint *scan = g_steal_pointer (&self->scan);
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (self->cancelled)
    { g_clear_error (&error); error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint operation cancelled"); }
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      g_clear_object (&scan);
      fpi_device_enroll_complete (device, NULL, error ? error : proto_error ("Enrollment ended without storage confirmation"));
      self->preparing_action = FALSE;
      self->enrollment_created = FALSE;
      OPENSSL_cleanse (self->enrollment_id, sizeof self->enrollment_id);
      OPENSSL_cleanse (self->nonce, sizeof self->nonce);
    }
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      if (!error)
        {
          FpPrint *wanted = NULL; fpi_device_get_verify_data (device, &wanted);
          gboolean match = self->matched && scan && fp_print_equal (wanted, scan);
          if (self->matched && scan && wanted)
            debug_print_comparison (wanted, scan);
          fpi_device_verify_report (device, match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, scan, NULL);
          scan = NULL;
        }
      else if (error->domain == FP_DEVICE_RETRY)
        { fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL, error); error = NULL; }
      g_clear_object (&scan); fpi_device_verify_complete (device, error);
    }
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    {
      if (!error)
        {
          GPtrArray *gallery = NULL; FpPrint *match = NULL;
          fpi_device_get_identify_data (device, &gallery);
          for (guint i = 0; scan && i < gallery->len; i++)
            {
              FpPrint *wanted = g_ptr_array_index (gallery, i);
              if (self->matched)
                debug_print_comparison (wanted, scan);
              if (fp_print_equal (wanted, scan)) { match = wanted; break; }
            }
          if (self->matched)
            fp_dbg ("Authenticated scan matched account gallery: %s (prints=%u)",
                    match ? "yes" : "no", gallery->len);
          fpi_device_identify_report (device, match, scan, NULL); scan = NULL;
        }
      else if (error->domain == FP_DEVICE_RETRY)
        { fpi_device_identify_report (device, NULL, NULL, error); error = NULL; }
      g_clear_object (&scan); fpi_device_identify_complete (device, error);
    }
  else { g_clear_object (&scan); fpi_device_action_error (device, error ? error : proto_error ("Unexpected interactive action")); }
  self->preparing_action = FALSE;
}

static void
enrollment_cancel_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length) error = proto_error ("Unexpected enrollment-cancel response");
  if (error) self->session.valid = FALSE;
  GError *operation_error = g_steal_pointer (&self->operation_error);
  if (error) g_clear_error (&error);
  self->enrollment_created = FALSE;
  OPENSSL_cleanse (self->enrollment_id, sizeof self->enrollment_id);
  finish_action (self, operation_error ? operation_error :
                 g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled"));
}

static void
enrollment_fail (FpiDevicePetaicmoc *self, GError *error)
{
  if (self->cancelled && !error)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled");
  /* Once libusb reports a transport error the reader may have reset or gone
   * away. Avoid another transfer from the error callback and make close() skip
   * its usual on-device MOC_CANCEL request. */
  if (error && error->domain == G_USB_DEVICE_ERROR)
    {
      self->setup_done = FALSE;
      self->session.valid = FALSE;
      self->enrollment_created = FALSE;
      OPENSSL_cleanse (self->enrollment_id, sizeof self->enrollment_id);
      OPENSSL_cleanse (self->nonce, sizeof self->nonce);
      finish_action (self, error);
      return;
    }
  if (self->enrollment_created && !self->commit_sent && self->setup_done && !self->inflight)
    {
      g_clear_error (&self->operation_error);
      self->operation_error = error;
      small (self, 0x0c, NULL, 0, 1, enrollment_cancel_cb);
      return;
    }
  OPENSSL_cleanse (self->enrollment_id, sizeof self->enrollment_id);
  OPENSSL_cleanse (self->nonce, sizeof self->nonce);
  finish_action (self, error ? error : proto_error ("Enrollment failed"));
}

static void
dump_data_extended_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  DumpDone done = self->dump_done;
  self->dump_done = NULL;
  if (!error && (length != 68 && length != 1364)) error = proto_error ("Unexpected DUMP_DATA response size");
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  if (done) done (self, error);
  else g_clear_error (&error);
}

static void
dump_data_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (error || length)
    {
      DumpDone done = self->dump_done;
      self->dump_done = NULL;
      if (done) done (self, error ? error : proto_error ("Unexpected DUMP_DATA setup payload"));
      else g_clear_error (&error);
      return;
    }
  guint8 ones[PT_EXT_OUT_PAYLOAD]; memset (ones, 1, sizeof ones);
  extended (self, 0x13, ones, dump_data_extended_cb);
}

static void
dump_data (FpiDevicePetaicmoc *self, guint8 mode, DumpDone done)
{
  guint8 parameter = mode;
  self->dump_done = done;
  small (self, 0x13, &parameter, 1, 1, dump_data_cb);
}

static void
enrollment_begin_nonce_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 32) error = proto_error ("Unexpected enrollment nonce length");
  if (!error && !pt_sdcp_enrollment_id (&self->session, payload, self->enrollment_id, &error)) { }
  if (error) { enrollment_fail (self, error); return; }
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  self->enrollment_created = TRUE;
  small (self, 0xc2, NULL, 0, 1, enrollment_created_cb);
}

static void
enrollment_created_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length) error = proto_error ("Unexpected CREATE_ENROLLMENT response");
  if (error) { enrollment_fail (self, error); return; }
  self->accepted_images = 0;
  self->max_samples = 12;
  self->preflight_enrollment = FALSE;
  self->need_release = TRUE;
  fpi_device_report_finger_status (FP_DEVICE (self), FP_FINGER_STATUS_PRESENT);
  enrollment_poll (self);
}

static void
start_enrollment (FpiDevicePetaicmoc *self)
{
  guint8 length[4] = { 32, 0, 0, 0 };
  small (self, 0xc6, length, sizeof length, 1, enrollment_begin_nonce_cb);
}

static void
preflight_time_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 4) error = proto_error ("Unexpected capture-time response");
  if (error) { enrollment_fail (self, error); return; }
  if (RAND_bytes (self->nonce, sizeof self->nonce) != 1)
    { enrollment_fail (self, proto_error ("Cannot generate fresh preflight nonce")); return; }
  small (self, 0xc7, self->nonce, sizeof self->nonce, 1, match_ack_cb);
}

static void
preflight_dump_done (FpiDevicePetaicmoc *self, GError *error)
{
  if (error) { enrollment_fail (self, error); return; }
  small (self, 0x31, NULL, 0, 1, preflight_time_cb);
}

static void
enrollment_capture_time_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 4) error = proto_error ("Unexpected capture-time response");
  if (error) { enrollment_fail (self, error); return; }
  small (self, 0xc5, NULL, 0, 0xff, enrollment_apply_cb);
}

static void
enrollment_dump_capture_done (FpiDevicePetaicmoc *self, GError *error)
{
  if (error) { enrollment_fail (self, error); return; }
  small (self, 0x31, NULL, 0, 1, enrollment_capture_time_cb);
}

static void
enrollment_capture_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 20) error = proto_error ("Unexpected enrollment capture report");
  if (!error && (gint32) pt_u32 (payload + 12) <= 0x8000)
    error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "Lift and place the finger again");
  if (error && error->domain == FP_DEVICE_RETRY && !self->cancelled)
    {
      fpi_device_enroll_progress (FP_DEVICE (self), self->accepted_images, NULL, error);
      self->need_release = TRUE;
      enrollment_poll (self);
      return;
    }
  if (error) { enrollment_fail (self, error); return; }
  dump_data (self, 2, enrollment_dump_capture_done);
}

static void
enrollment_commit_dump_done (FpiDevicePetaicmoc *self, GError *error)
{
  if (error) { enrollment_fail (self, error); return; }
  self->commit_sent = TRUE;
  guint8 payload[80];
  if (!pt_enrollment_commit_payload (self->enrollment_id, self->enrollment_subfactor, payload, &error))
    { enrollment_fail (self, error); return; }
  small (self, 0xc3, payload, sizeof payload, 1, enrollment_commit_cb);
  OPENSSL_cleanse (payload, sizeof payload);
}

static void
enrollment_commit_readback_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error) pt_database_size (payload, length, &self->count, &error);
  if (error || !self->count || self->count > G_N_ELEMENTS (self->records))
    { self->verifying_commit = FALSE; enrollment_fail (self, error ? error : proto_error ("Invalid post-commit storage count")); return; }
  self->record_index = 0;
  self->commit_record_found = FALSE;
  self->verifying_commit = TRUE;
  guint8 index = 0;
  small (self, 0xd9, &index, 1, 1, record_cb);
}

static void
enrollment_commit_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  /* A failed response is ambiguous after the commit write. Query storage once;
   * never resend a commit whose outcome may already be durable. */
  if (!error && (length != 12 || (pt_u32 (payload) != 0 && pt_u32 (payload) != 90) || payload[10] || payload[11]))
    error = proto_error ("Unexpected enrollment commit result");
  if (error)
    {
      g_clear_error (&self->operation_error);
      self->operation_error = error;
      small (self, 0xd5, NULL, 0, 1, enrollment_commit_readback_cb);
      return;
    }
  dump_data (self, 2, enrollment_post_commit_dump_done);
}

static void
enrollment_post_commit_dump_done (FpiDevicePetaicmoc *self, GError *error)
{
  if (error)
    {
      g_clear_error (&self->operation_error);
      self->operation_error = error;
    }
  small (self, 0xd5, NULL, 0, 1, enrollment_commit_readback_cb);
}

static void
enrollment_commit_start_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 120) error = proto_error ("Unexpected enrollment matching result");
  if (error) { enrollment_fail (self, error); return; }
  dump_data (self, 2, enrollment_commit_dump_done);
}

static void
enrollment_apply_dump_done (FpiDevicePetaicmoc *self, GError *error)
{
  if (error) { enrollment_fail (self, error); return; }
  if (self->enrollment_event == 0xa7)
    small (self, 0xc1, NULL, 0, 0xaf, enrollment_commit_start_cb);
  else
    {
      self->need_release = TRUE;
      fpi_device_report_finger_status (FP_DEVICE (self), FP_FINGER_STATUS_PRESENT);
      enrollment_poll (self);
    }
}

static void
enrollment_apply_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  guint previous_accepted = self->accepted_images;
  guint result = 0, accepted = 0, maximum = 0; gboolean complete = FALSE;
  if (!error && !pt_enrollment_result (self->response_event, payload, length, &result,
                                       &accepted, &maximum, &complete, &error)) { }
  if (!error && self->max_samples && maximum != self->max_samples)
    error = proto_error ("Enrollment sample limit changed during operation");
  if (!error && self->response_event == 0xa0 && (result != 3 || accepted != previous_accepted))
    error = proto_error ("Rejected image changed the accepted sample count");
  if (!error && self->response_event != 0xa0 && accepted != previous_accepted + 1)
    error = proto_error ("Accepted enrollment image did not advance by one sample");
  if (error) { enrollment_fail (self, error); return; }
  self->max_samples = maximum;
  self->accepted_images = accepted;
  self->enrollment_event = self->response_event;
  if (self->response_event == 0xa0)
    {
      g_autoptr(GError) retry = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL, "Image not accepted; lift and try again");
      fpi_device_enroll_progress (FP_DEVICE (self), accepted, NULL, g_steal_pointer (&retry));
    }
  else
    fpi_device_enroll_progress (FP_DEVICE (self), accepted, NULL, NULL);
  if (complete && accepted != maximum)
    { enrollment_fail (self, proto_error ("Enrollment completed with an incomplete sample count")); return; }
  if (complete)
    {
      dump_data (self, 2, enrollment_apply_dump_done);
      return;
    }
  self->retries++;
  if (self->retries > 40)
    { enrollment_fail (self, proto_error ("Enrollment exceeded the sample retry limit")); return; }
  dump_data (self, 2, enrollment_apply_dump_done);
}

static void
enrollment_poll (FpiDevicePetaicmoc *self)
{
  if (self->cancelled) { enrollment_fail (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled")); return; }
  poll_finger (FP_DEVICE (self), NULL);
}

static void
cleanup_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length) error = proto_error ("Unexpected cancellation payload");
  if (error)
    {
      self->session.valid = FALSE;
      if (self->operation_error) { g_clear_error (&self->operation_error); }
    }
  else error = g_steal_pointer (&self->operation_error);
  OPENSSL_cleanse (self->nonce, sizeof self->nonce);
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  OPENSSL_cleanse (self->outgoing, sizeof self->outgoing);
  finish_action (self, error);
}

static void
cleanup (FpiDevicePetaicmoc *self, GError *error)
{
  self->operation_error = error;
  small (self, 0x0c, NULL, 0, 1, cleanup_cb);
}

static void
match_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  guint8 id[32], subfactor;
  if (!error) pt_sdcp_match (&self->session, self->nonce, payload, length, &self->matched, id, &subfactor, &error);
  fp_dbg ("Authenticated match decision: %s", self->matched ? "match" : "nonmatch");
  if (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL)
    {
      if (error) { enrollment_fail (self, error); return; }
      if (self->matched)
        { enrollment_fail (self, fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE)); return; }
      OPENSSL_cleanse (self->incoming, sizeof self->incoming);
      OPENSSL_cleanse (self->nonce, sizeof self->nonce);
      start_enrollment (self);
      return;
    }
  if (!error && self->matched)
    {
      gboolean known = FALSE;
      for (guint i = 0; i < self->count; i++)
        if (self->records[i].subfactor == subfactor && !CRYPTO_memcmp (id, self->records[i].id, 32)) known = TRUE;
      if (!known) error = proto_error ("Authenticated identity outside open-time record snapshot");
      else self->scan = scan_print (self, id, subfactor);
    }
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  cleanup (self, error);
}

static void
match_ack_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (error) { cleanup (self, error); return; }
  /* Once acknowledged, complete the extended exchange even if cancellation arrives. */
  guint8 dummy[PT_EXT_OUT_PAYLOAD];
  for (guint i = 0; i < sizeof dummy; i++) dummy[i] = i;
  extended (self, 0xc7, dummy, match_cb);
}

static void
capture_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && length != 20) error = proto_error ("Unexpected capture report");
  if (!error) fp_dbg ("Capture quality=%u area=%u spoof_score=%u", payload[0], pt_u16 (payload + 2), pt_u32 (payload + 12));
  if (!error && (gint32) pt_u32 (payload + 12) <= 0x8000)
    error = fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
  if (!error && self->cancelled) error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Cancelled after capture");
  if (error && error->domain == FP_DEVICE_RETRY &&
      fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL && self->preflight_enrollment)
    {
      fpi_device_enroll_progress (FP_DEVICE (self), 0, NULL, error);
      self->need_release = TRUE;
      enrollment_poll (self);
      return;
    }
  if (error) { if (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL) enrollment_fail (self, error); else cleanup (self, error); return; }
  if (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL && self->preflight_enrollment)
    {
      self->preflight_enrollment = FALSE;
      /* The vendor's enrollment preflight checks the touched finger against
       * existing records before requesting a new secure enrollment ID. */
      dump_data (self, 1, preflight_dump_done);
      return;
    }
  if (RAND_bytes (self->nonce, 32) != 1) { cleanup (self, proto_error ("Cannot generate match nonce")); return; }
  small (self, 0xc7, self->nonce, 32, 1, match_ack_cb);
}

static void
finger_cb (FpiDevicePetaicmoc *self, const guint8 *payload, gsize length, GError *error)
{
  if (!error && (length != 4 || pt_u32 (payload) > 1)) error = proto_error ("Unexpected finger-status response");
  gboolean enrolling = fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL;
  if (error) { if (enrolling) enrollment_fail (self, error); else cleanup (self, error); return; }
  if (self->cancelled)
    {
      if (enrolling) enrollment_fail (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled"));
      else cleanup (self, NULL);
      return;
    }
  if (self->need_release)
    {
      if (!pt_u32 (payload))
        { self->need_release = FALSE; fpi_device_report_finger_status (FP_DEVICE (self), FP_FINGER_STATUS_NEEDED); }
      fpi_device_add_timeout (FP_DEVICE (self), 100, poll_finger, NULL, NULL);
      return;
    }
  if (pt_u32 (payload))
    {
      fpi_device_report_finger_status (FP_DEVICE (self), FP_FINGER_STATUS_PRESENT);
      if (enrolling && !self->preflight_enrollment)
        small (self, 0xc4, NULL, 0, 1, enrollment_capture_cb);
      else
        small (self, 0xc0, NULL, 0, 1, capture_cb);
    }
  else fpi_device_add_timeout (FP_DEVICE (self), 100, poll_finger, NULL, NULL);
}

static void
poll_finger (FpDevice *device, gpointer unused)
{
  FpiDevicePetaicmoc *self = PT_SELF (device);
  if (self->cancelled)
    {
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_ENROLL)
        enrollment_fail (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Fingerprint enrollment cancelled"));
      else cleanup (self, NULL);
      return;
    }
  small (self, 0x30, NULL, 0, 1, finger_cb);
}

static void
pt_interactive (FpDevice *device)
{
  FpiDevicePetaicmoc *self = PT_SELF (device);
  self->cancelled = self->matched = FALSE; g_clear_object (&self->scan);
  self->enrollment_created = self->commit_sent = self->preflight_enrollment = FALSE;
  self->verifying_commit = self->commit_record_found = FALSE;
  self->accepted_images = self->max_samples = self->retries = 0;
  self->enrollment_subfactor = 0xf6;
  if (!self->session.valid) { finish_action (self, proto_error ("No validated SDCP session; reopen reader")); return; }
  if (!self->count && fpi_device_get_current_action (device) != FPI_DEVICE_ACTION_ENROLL)
    { finish_action (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND, "No enrolled prints on reader")); return; }
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
  self->preparing_action = TRUE; self->need_release = FALSE; self->retries = 0;
  prepare_connection (self);
}

static void
pt_cancel (FpDevice *device)
{
  FpiDevicePetaicmoc *self = PT_SELF (device);
  self->cancelled = TRUE;
  if (self->read_cancel) g_cancellable_cancel (self->read_cancel);
}

static gint
pt_discover (GUsbDevice *usb)
{
  return g_usb_device_get_release (usb) == 0x0100 && g_usb_device_get_device_class (usb) == 0xff ? 100 : 0;
}

static void
pt_finalize (GObject *object)
{
  FpiDevicePetaicmoc *self = PT_SELF (object);
  pt_sdcp_clear (&self->session); g_clear_object (&self->read_cancel);
  g_clear_error (&self->operation_error); g_clear_object (&self->scan);
  OPENSSL_cleanse (self->records, sizeof self->records);
  OPENSSL_cleanse (self->incoming, sizeof self->incoming);
  OPENSSL_cleanse (self->outgoing, sizeof self->outgoing);
  OPENSSL_cleanse (self->nonce, sizeof self->nonce);
  G_OBJECT_CLASS (fpi_device_petaicmoc_parent_class)->finalize (object);
}

static void fpi_device_petaicmoc_init (FpiDevicePetaicmoc *self) { }
static void
fpi_device_petaicmoc_class_init (FpiDevicePetaicmocClass *klass)
{
  G_OBJECT_CLASS (klass)->finalize = pt_finalize;
  klass->id = "petaicmoc";
  klass->full_name = "PetaIC SDCP Fingerprint Reader";
  klass->type = FP_DEVICE_TYPE_USB; klass->id_table = id_table;
  klass->scan_type = FP_SCAN_TYPE_PRESS; klass->nr_enroll_stages = 12;
  klass->usb_discover = pt_discover; klass->open = pt_open; klass->close = pt_close;
  klass->enroll = pt_interactive; klass->verify = pt_interactive; klass->identify = pt_interactive;
  klass->cancel = pt_cancel;
  klass->features = FP_DEVICE_FEATURE_VERIFY | FP_DEVICE_FEATURE_IDENTIFY;
}
