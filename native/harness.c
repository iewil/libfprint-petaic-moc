/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "libfprint/fprint.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static gboolean cancel_later (gpointer token) { g_cancellable_cancel (token); return G_SOURCE_REMOVE; }

static void
progress (FpDevice *device, gint stage, FpPrint *print, gpointer unused, GError *error)
{
  g_print ("Registration stage %d%s\n", stage, error ? " needs retry" : " completed");
}

static void
matched_cb (FpDevice *device, FpPrint *match, FpPrint *scan, gpointer unused, GError *error)
{
  g_print ("Result: %s\n", error ? "retry" : match ? "matched requested Linux print" : "no match for requested Linux print");
}

static gboolean
write_private (const gchar *path, const guint8 *bytes, gsize size, GError **error)
{
  int fd = open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot exclusively create private print file"); return FALSE; }
  gsize offset = 0;
  while (offset < size)
    {
      ssize_t n = write (fd, bytes + offset, size - offset);
      if (n <= 0) { close (fd); unlink (path); g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot save print metadata"); return FALSE; }
      offset += n;
    }
  if (close (fd)) { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot close print metadata file"); return FALSE; }
  return TRUE;
}

int
main (int argc, char **argv)
{
  if (argc < 2 || (strcmp (argv[1], "--probe") && strcmp (argv[1], "--enroll-fresh") &&
                  strcmp (argv[1], "--verify") && strcmp (argv[1], "--verify-refresh") && strcmp (argv[1], "--identify") &&
                  strcmp (argv[1], "--identify-foreign") && strcmp (argv[1], "--cancel-test")))
    { g_printerr ("Usage: %s --probe | --enroll-fresh PRIVATE_FILE | --verify PRIVATE_FILE | --verify-refresh PRIVATE_FILE PRIVATE_SCAN_FILE | --identify PRIVATE_FILE | --identify-foreign PRIVATE_FILE | --cancel-test\n", argv[0]); return 2; }
  if ((!strcmp (argv[1], "--enroll-fresh") || !strcmp (argv[1], "--verify") || !strcmp (argv[1], "--identify") || !strcmp (argv[1], "--identify-foreign")) && argc != 3) return 2;
  if (!strcmp (argv[1], "--verify-refresh") && argc != 4) return 2;
  g_autoptr(GError) error = NULL;
  g_autoptr(FpContext) context = fp_context_new ();
  fp_context_enumerate (context);
  GPtrArray *devices = fp_context_get_devices (context);
  FpDevice *device = NULL;
  for (guint i = 0; i < devices->len; i++)
    if (!strcmp (fp_device_get_driver (g_ptr_array_index (devices, i)), "petaicmoc"))
      { if (device) { g_printerr ("Expected one reader\n"); return 1; } device = g_ptr_array_index (devices, i); }
  if (!device) { g_printerr ("No PetaIC reader discovered\n"); return 1; }
  if (!fp_device_open_sync (device, NULL, &error)) goto failed;
  g_print ("Native petaicmoc opened: SDCP and reader/firmware pin validated\n");
  gboolean ok = TRUE;
  if (!strcmp (argv[1], "--enroll-fresh"))
    {
      g_autoptr(FpPrint) template = fp_print_new (device);
      fp_print_set_username (template, g_get_user_name ());
      fp_print_set_finger (template, FP_FINGER_RIGHT_INDEX);
      g_print ("READY: Enroll a new finger directly on this reader\n");
      g_autoptr(FpPrint) print = fp_device_enroll_sync (device, g_steal_pointer (&template), NULL, progress, NULL, &error);
      if (!print) ok = FALSE;
      else
        {
          g_autofree guint8 *data = NULL; gsize length;
          ok = fp_print_serialize (print, &data, &length, &error) && write_private (argv[2], data, length, &error);
          if (ok) g_print ("Linux print metadata saved privately; new reader template committed\n");
        }
    }
  else if (!strcmp (argv[1], "--verify") || !strcmp (argv[1], "--verify-refresh") || !strcmp (argv[1], "--identify") || !strcmp (argv[1], "--identify-foreign"))
    {
      g_autofree gchar *bytes = NULL; gsize length;
      if (!g_file_get_contents (argv[2], &bytes, &length, &error)) ok = FALSE;
      else
        {
          g_autoptr(FpPrint) print = fp_print_deserialize ((guint8 *) bytes, length, &error);
          gboolean matched = FALSE;
          if (!print) ok = FALSE;
          else
            {
              if (!strcmp (argv[1], "--identify-foreign"))
                {
                  /* Test a valid device match against a different host gallery ID. */
                  g_autoptr(GVariant) data = NULL;
                  g_object_get (print, "fpi-data", &data, NULL);
                  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(uayayayy)")))
                    { g_printerr ("Unexpected native print schema\n"); return 1; }
                  guint8 foreign[32] = {0};
                  GVariant *altered = g_variant_new ("(u@ay@ay@ayy)", 1,
                      g_variant_get_child_value (data, 1), g_variant_get_child_value (data, 2),
                      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, foreign, 32, 1),
                      g_variant_get_byte (g_variant_get_child_value (data, 4)));
                  g_object_set (print, "fpi-data", altered, NULL);
                }
              g_print ("READY: Touch the finger to test against the registered Linux print\n");
              if (!strcmp (argv[1], "--verify") || !strcmp (argv[1], "--verify-refresh"))
                {
                  g_autoptr(FpPrint) scan = NULL;
                  ok = fp_device_verify_sync (device, print, NULL, matched_cb, NULL,
                                              &matched, !strcmp (argv[1], "--verify-refresh") ? &scan : NULL, &error);
                  if (ok && scan && !strcmp (argv[1], "--verify-refresh"))
                    {
                      g_autofree guint8 *serialized = NULL; gsize serialized_length;
                      ok = fp_print_serialize (scan, &serialized, &serialized_length, &error) &&
                           write_private (argv[3], serialized, serialized_length, &error);
                      if (ok) g_print ("Authenticated scan print saved privately for metadata diagnosis\n");
                    }
                }
              else
                {
                  g_autoptr(GPtrArray) gallery = g_ptr_array_new ();
                  FpPrint *match = NULL;
                  g_ptr_array_add (gallery, print);
                  ok = fp_device_identify_sync (device, gallery, NULL, matched_cb, NULL, &match, NULL, &error);
                  matched = match != NULL; g_clear_object (&match);
                }
              if (ok) g_print ("Native %s decision: %s\n", argv[1] + 2, matched ? "match" : "nonmatch");
            }
        }
    }
  else if (!strcmp (argv[1], "--cancel-test"))
    {
      g_autoptr(GCancellable) cancellable = g_cancellable_new ();
      g_autoptr(FpPrint) template = fp_print_new (device);
      guint timer = g_timeout_add (1000, cancel_later, cancellable);
      g_print ("READY: Leave reader untouched for the cancellation test\n");
      g_autoptr(FpPrint) print = fp_device_enroll_sync (device, g_steal_pointer (&template), cancellable, progress, NULL, &error);
      if (!g_cancellable_is_cancelled (cancellable)) g_source_remove (timer);
      ok = !print && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
      if (ok) { g_clear_error (&error); g_print ("Native cancellation completed\n"); }
    }
  {
    g_autoptr(GError) close_error = NULL;
    if (!fp_device_close_sync (device, NULL, &close_error))
      { if (!error) error = g_steal_pointer (&close_error); ok = FALSE; }
  }
  if (!ok || error) goto failed;
  return 0;
failed:
  g_printerr ("Native harness failed: %s\n", error ? error->message : "unexpected result");
  return 1;
}
