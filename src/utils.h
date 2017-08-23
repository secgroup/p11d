/* See LICENSE file for copyright and license details. */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "pkcs11_unix.h"

void die(const char *msg);
void check_ret(CK_RV rv, const char *msg);
void initialize();
void finalize();
CK_SLOT_ID get_slot(unsigned int slot_n);
CK_SESSION_HANDLE start_session(CK_SLOT_ID slot_id);
void end_session(CK_SESSION_HANDLE session);
void login(CK_SESSION_HANDLE session, CK_BYTE *pin);
void logout(CK_SESSION_HANDLE session);
void strcat_repr_hex(char *buf, CK_BYTE_PTR data, CK_ULONG data_len);
void show_hex(CK_BYTE_PTR data, CK_ULONG data_len);
void strcat_repr_template(char *buf, CK_ATTRIBUTE_PTR template, CK_ULONG attr_count);
void enumerate_keys(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
	CK_ULONG attr_count);
CK_OBJECT_HANDLE get_key(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
	CK_ULONG attr_count);
void p11d_get_attribute_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
        CK_ATTRIBUTE_PTR template, CK_ULONG attr_count);
void p11d_set_attribute_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, 
        CK_ATTRIBUTE_PTR template, CK_ULONG attr_count);
void wrap_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, 
	CK_BYTE_PTR *wrapped_key, CK_ULONG_PTR p_wrapped_key_len);
void unwrap_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
	CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
	CK_ULONG attribute_count, CK_OBJECT_HANDLE_PTR key);
void p11d_encrypt(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE key, CK_BYTE_PTR p_data, CK_ULONG data_len,
	CK_BYTE_PTR *p_encrypted_data, CK_ULONG_PTR p_encrypted_data_len);
void decrypt(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE key, CK_BYTE_PTR p_encrypted_data, 
	CK_ULONG encrypted_data_len, CK_BYTE_PTR *p_data, 
	CK_ULONG_PTR p_data_len);
void generate_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key);
void create_object(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
	CK_ULONG count, CK_OBJECT_HANDLE_PTR key);

#endif /* UTILS_H */
