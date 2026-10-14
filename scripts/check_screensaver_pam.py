#!/usr/bin/env python3
"""Test Cinnamon's PAM stack without ever collecting a password.

Touch a registered finger for a positive test. --expect-fallback tests that a
rejected/no-touch attempt reaches the existing password path, then aborts it.
"""
import argparse
import ctypes as C
import getpass
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-fallback', action='store_true')
    args = parser.parse_args()
    class Message(C.Structure):
        _fields_ = [('style', C.c_int), ('text', C.c_char_p)]
    class Response(C.Structure):
        _fields_ = [('text', C.c_void_p), ('code', C.c_int)]
    Callback = C.CFUNCTYPE(C.c_int, C.c_int, C.POINTER(C.POINTER(Message)),
                          C.POINTER(C.POINTER(Response)), C.c_void_p)
    class Conversation(C.Structure):
        _fields_ = [('callback', Callback), ('data', C.c_void_p)]
    pam = C.CDLL('libpam.so.0')
    libc = C.CDLL('libc.so.6')
    libc.calloc.argtypes = [C.c_size_t, C.c_size_t]
    libc.calloc.restype = C.c_void_p
    fallback = False

    @Callback
    def conversation(count, messages, responses, data):
        nonlocal fallback
        if not 1 <= count <= 32: return 19  # PAM_CONV_ERR
        for index in range(count):
            message = messages[index].contents
            if message.style in (1, 2):  # Password / other credential input
                fallback = True
                print('Existing password path requested; test aborts without collecting credentials.', flush=True)
                return 19
            if message.style not in (3, 4): return 19
            print((message.text or b'').decode('utf-8', errors='replace'), flush=True)
        memory = libc.calloc(count, C.sizeof(Response))
        if not memory: return 5  # PAM_BUF_ERR
        responses[0] = C.cast(memory, C.POINTER(Response))
        return 0

    pam.pam_start.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(Conversation), C.POINTER(C.c_void_p)]
    pam.pam_start.restype = C.c_int
    pam.pam_authenticate.argtypes = [C.c_void_p, C.c_int]
    pam.pam_authenticate.restype = C.c_int
    pam.pam_end.argtypes = [C.c_void_p, C.c_int]
    pam.pam_end.restype = C.c_int
    handle = C.c_void_p()
    conv = Conversation(conversation, None)
    status = pam.pam_start(b'cinnamon-screensaver', getpass.getuser().encode(), C.byref(conv), C.byref(handle))
    if status != 0: raise RuntimeError(f'pam_start returned {status}')
    print('READY: ' + ('Use an unenrolled finger or leave the reader untouched.' if args.expect_fallback else 'Touch your registered finger.'), flush=True)
    try:
        status = pam.pam_authenticate(handle, 0)
    finally:
        pam.pam_end(handle, status)
    passed = (fallback and status != 0) if args.expect_fallback else (status == 0 and not fallback)
    print(json.dumps({'pam_status': status, 'password_fallback_requested': fallback,
                      'fingerprint_authentication_succeeded': status == 0 and not fallback,
                      'test_passed': passed}))
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'PAM test failed: {error}', file=sys.stderr)
        sys.exit(1)
