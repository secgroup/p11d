/* See LICENSE file for copyright and license details. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "pkcs11_unix.h"
#include "utils.h"
#include "p11d.h"

void
die(const char *msg) {
	fprintf(stderr, "[E] %s\n", msg);
	exit(EXIT_FAILURE);
}

void
check_ret(CK_RV rv, const char *msg) {
	if(rv != CKR_OK) {
		fprintf(stderr, "[E] %s: 0x%08lx\n", msg, rv);
		exit(EXIT_FAILURE);
	}
}

void
initialize() {
	CK_RV rv;

	/* initialize the session: no need for threading, se we pass NULL */
	rv = C_Initialize(NULL);
	check_ret(rv, "Initialize");
}

void
finalize() {
	CK_RV rv;

	rv = C_Finalize(NULL);
	check_ret(rv, "Finalize");
}

CK_SLOT_ID
get_slot(unsigned int slot_n) {
	CK_RV rv;
	CK_SLOT_ID slot_id;
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG slot_count;

	slot_count = 0;
	/* read the number of slots containing a token by providing CK_TRUE
	 * as the first parameter and set the number of slots in the
	 * slots_count variable */
	rv = C_GetSlotList(CK_TRUE, NULL, &slot_count);
	check_ret(rv, "Get slot list");
	if(slot_count < 1) {
		die("No slots available");
	}
	/* allocate memory for the needed slots */
	slot_list = calloc(slot_count, sizeof(CK_SLOT_ID));
	/* get the actual list of slots */
	C_GetSlotList(CK_TRUE, slot_list, &slot_count);
	check_ret(rv, "Get slot list");
	/* select the provided slot */
	slot_id = slot_list[slot_n];
	/* free the slot list */
	free(slot_list);

	return slot_id;
}

CK_SESSION_HANDLE
start_session(CK_SLOT_ID slot_id) {
	CK_RV rv;
	CK_SESSION_HANDLE session;

	/* CKF_SERIAL_SESSION must be always set for legacy compatibility,
	 * since we want to get read and write access to the token we enable
	 * the bit associated with the CKF_RW_SESSION flag. 3rd and 4th
	 * parameters are used to provide callback functions for the library to
	 * notify certain events (not needed now) */
	rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &session);
	check_ret(rv, "Open session");

	return session;
}

void
end_session(CK_SESSION_HANDLE session) {
	CK_RV rv;

	rv = C_CloseSession(session);
	check_ret(rv, "Close session");
}

void
login(CK_SESSION_HANDLE session, CK_BYTE *pin) {
	CK_RV rv;

	if(pin) {
		rv = C_Login(session, CKU_USER, pin, strlen((char *)pin));
		check_ret(rv, "Login");
	}
}

void
logout(CK_SESSION_HANDLE session) {
	CK_RV rv;
	
	rv = C_Logout(session);
	/* if we were not logged in before executing the logout call the
	 * following error is returned */
	if(rv != CKR_USER_NOT_LOGGED_IN) {
		check_ret(rv, "Logout");
	}
}

void
strcat_repr_hex(char *buf, CK_BYTE_PTR data, CK_ULONG data_len) {
	unsigned int i, offset;

	strcat(buf, "\"");
	offset = strlen(buf);
	for(i=0; i<data_len; i++) {
		snprintf((char *) &(buf[offset+i*2]), 3, "%02x", data[i]);
	}
	strcat(buf, "\"");
}

void
show_hex(CK_BYTE_PTR data, CK_ULONG data_len) {
	char buf[2048];

	memset(buf, 0, sizeof(buf));
	strcat_repr_hex(buf, data, data_len);
	printf("%s\n", buf);
}

void
strcat_repr_template(char *buf, CK_ATTRIBUTE_PTR template, CK_ULONG attr_count) {
	unsigned int i, j;
	char *delim = "";
	CK_ATTRIBUTE_TYPE attr_types[] = {
		CKA_LABEL, CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP,
		CKA_UNWRAP, CKA_KEY_TYPE, CKA_EXTRACTABLE, CKA_VALUE
	};
	char *attr_labels[] = {
		"label",
		"sensitive",
		"encrypt",
		"decrypt",
		"wrap",
		"unwrap",
		"keytype",
		"extractable",
		"value"
	};

	strcat(buf, "{");
	for(i=0; i<attr_count; i++) {
		for(j=0; j<9; j++) {
			if(template[i].type == attr_types[j]) {
				strcat(buf, delim);
				strcat(buf, "\"");
				strcat(buf, attr_labels[j]);
				strcat(buf, "\": ");
				strcat_repr_hex(buf, template[i].pValue, template[i].ulValueLen);
				delim = ", ";
				break;
			}
		}
	}
	strcat(buf, "}");
}

void
enumerate_keys(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
	CK_ULONG attr_count) {
	CK_RV rv;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object;
	unsigned int object_counter = 0;

	/* find all the keys matching the provided template */
	rv = C_FindObjectsInit(session, template, attr_count);
	check_ret(rv, "Find objects init");
	/* search for keys that match a template, one at a time */
	rv = C_FindObjects(session, &object, 1, &object_count);
	check_ret(rv, "Find Objects");
	while(object_count > 0) {
		object_counter++;
		rv = C_FindObjects(session, &object, 1, &object_count);
		check_ret(rv, "Find Objects");
	}
	printf("[I] Found %d key(s)\n", object_counter);

	rv = C_FindObjectsFinal(session);
	check_ret(rv, "Find objects final");
}

CK_OBJECT_HANDLE
get_key(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
	CK_ULONG attr_count) {
	CK_RV rv;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object;

	/* find all the keys matching the provided template */
	rv = C_FindObjectsInit(session, template, attr_count);
	check_ret(rv, "Find objects init");
	/* search for keys that match a template, one at a time */
	rv = C_FindObjects(session, &object, 1, &object_count);
	check_ret(rv, "Find objects");
	rv = C_FindObjectsFinal(session);
	check_ret(rv, "Find objects final");

	return object;
}

void
p11d_get_attribute_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
        CK_ATTRIBUTE_PTR template, CK_ULONG attr_count) {
	CK_RV rv;
	unsigned int i;

	rv = C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "Get attribute value (sizes)");
	/* allocate memory for all the attributes found */
	for(i=0; i<attr_count; i++) {
		if(template[i].ulValueLen > 0) {
			template[i].pValue = malloc(template[i].ulValueLen);
		}
	}
	/* do another call to copy the attribute values into the buffer
	 * located at pValue  */
	rv = C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "Get attribute value");
}

void
p11d_set_attribute_value(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
	CK_ATTRIBUTE_PTR template, CK_ULONG attr_count) {
	CK_RV rv;
	
	rv = C_SetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "Set attribute value");
}

void
wrap_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, 
	CK_BYTE_PTR *p_wrapped_key, CK_ULONG_PTR p_wrapped_key_len) {
	CK_RV rv;

	/* find the number of bytes which would suffice to hold the
	 * cryptographic output produced by the function */
	rv = C_WrapKey(session, p_mechanism, wrapping_key, key, NULL_PTR,
		p_wrapped_key_len);
	check_ret(rv, "Wrap key (find len)");
	*p_wrapped_key = malloc(*p_wrapped_key_len * sizeof(CK_BYTE));
	/* perform the wrap operation */
	rv = C_WrapKey(session, p_mechanism, wrapping_key, key, *p_wrapped_key,
		p_wrapped_key_len);
	check_ret(rv, "Wrap key");
}

void
unwrap_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
	CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
	CK_ULONG attribute_count, CK_OBJECT_HANDLE_PTR key) {
	CK_RV rv;

	rv = C_UnwrapKey(session, p_mechanism, unwrapping_key, wrapped_key,
		wrapped_key_len, template, attribute_count, key);
	check_ret(rv, "Unwrap key");
}

void
p11d_encrypt(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE key, CK_BYTE_PTR p_data, CK_ULONG data_len,
	CK_BYTE_PTR *p_encrypted_data, CK_ULONG_PTR p_encrypted_data_len) {
	CK_RV rv;

	/* initialization */
	rv = C_EncryptInit(session, p_mechanism, key);
	check_ret(rv, "Encrypt init");
	/* find the encrypted data len */
	rv = C_Encrypt(session, p_data, data_len, NULL_PTR,
		p_encrypted_data_len);
	check_ret(rv, "Encrypt (find len)");
	/* allocate the needed space */
	p_encrypted_data = malloc(*p_encrypted_data_len * sizeof(CK_BYTE));
	/* perform the encrypt operation */
	rv = C_Encrypt(session, p_data, data_len, *p_encrypted_data,
		p_encrypted_data_len);
	check_ret(rv, "Encrypt");

}

void
decrypt(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE key, CK_BYTE_PTR p_encrypted_data, 
	CK_ULONG encrypted_data_len, CK_BYTE_PTR *p_data, 
	CK_ULONG_PTR p_data_len) {
	CK_RV rv;

	/* initialization */
	rv = C_DecryptInit(session, p_mechanism, key);
	check_ret(rv, "Decrypt init");
	/* find the data len */
	rv = C_Decrypt(session, p_encrypted_data, encrypted_data_len, NULL_PTR,
		p_data_len);
	check_ret(rv, "Decrypt (find len)");
	/* allocate the needed space */
	*p_data = malloc(*p_data_len * sizeof(CK_BYTE));
	/* perform the decrypt operation */
	rv = C_Decrypt(session, p_encrypted_data, encrypted_data_len, *p_data,
		p_data_len);
	check_ret(rv, "Decrypt");
}

void
generate_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
	CK_RV rv;

	rv = C_GenerateKey(session, p_mechanism, template, count, key);
	check_ret(rv, "Generate key");
}

void
create_object(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
	CK_RV rv;

	rv = C_CreateObject(session, template, count, key);
	check_ret(rv, "Create object");
}
