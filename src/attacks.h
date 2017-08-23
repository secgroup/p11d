/*
 * Description: attacks.h, header file for attakcs.c
 */

#ifndef ATTACKS_H
#define ATTACKS_H

#include "pkcs11_unix.h"

void attack_wrap_unwrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_wrap_unwrap_self(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_wrap_decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_wrap_decrypt_mutual(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_re_import(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_distr_wrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key);
void attack_distr_decrypt(CK_SESSION_HANDLE session);
CK_OBJECT_HANDLE create_sensitive_wrapping_key(CK_SESSION_HANDLE session);
CK_OBJECT_HANDLE create_sensitive_decrypt_key(CK_SESSION_HANDLE session);

#endif /* ATTACKS_H */
