#include <stdlib.h>
#include <stdio.h>
#include "pkcs11_unix.h"
#include "utils.h"
#include "attacks.h"

void
digest_key(CK_SESSION_HANDLE session, CK_MECHANISM_PTR p_mechanism,
	CK_OBJECT_HANDLE key, CK_BYTE_PTR *p_digest_data, 
	CK_ULONG_PTR p_digest_data_len) {
	CK_BYTE_PTR data = NULL;
	CK_ULONG data_len = 0;
	CK_RV rv;

	/* initialization */
	rv = C_DigestInit(session, p_mechanism);
	check_ret(rv, "Digest init");
	rv = C_DigestUpdate(session, data, data_len);
	check_ret(rv, "Digest update");
	rv = C_DigestKey(session, key);
	check_ret(rv, "Digest key");
	rv = C_DigestFinal(session, *p_digest_data, p_digest_data_len);
	check_ret(rv, "Digest final");
}

CK_OBJECT_HANDLE *
create_key_pair(CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_HANDLE publicKey, privateKey;
     CK_MECHANISM mechanism = {
          CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
     };
     CK_ULONG modulusBits = 1024;
     CK_BYTE publicExponent[] = { 1, 0, 1 };
     CK_BYTE subject[] = "mykeyyo";
     CK_BYTE id[] = {0xa1};
     CK_BBOOL true = CK_TRUE;
     CK_ATTRIBUTE publicKeyTemplate[] = {
          {CKA_ID, id, 3},
          {CKA_LABEL, subject, 7},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_ENCRYPT, &true, sizeof(true)},
          {CKA_VERIFY, &true, sizeof(true)},
          {CKA_WRAP, &true, sizeof(true)},
          {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
          {CKA_PUBLIC_EXPONENT, publicExponent, 3}
     };
     CK_ATTRIBUTE privateKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, 5},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_PRIVATE, &true, sizeof(true)},
          {CKA_SENSITIVE, &true, sizeof(true)},
          {CKA_DECRYPT, &true, sizeof(true)},
          {CKA_SIGN, &true, sizeof(true)},
          {CKA_UNWRAP, &true, sizeof(true)}
     };

     rv = C_GenerateKeyPair(session,
                            &mechanism,
                            publicKeyTemplate, 8,
                            privateKeyTemplate, 8,
                            &publicKey,
                            &privateKey);
     check_ret(rv, "generate key pair");

     CK_OBJECT_HANDLE_PTR keys = malloc(sizeof(CK_OBJECT_HANDLE) * 2);
     keys[0] = publicKey;
     keys[1] = privateKey;

     return keys;
}

int
main(int argc, char **argv) {
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_CLASS class_secret = CKO_SECRET_KEY;
	CK_KEY_TYPE type_des = CKK_DES;
	CK_KEY_TYPE type_des3 = CKK_DES3;
	CK_KEY_TYPE type_aes = CKK_AES;
	CK_BYTE *pin = NULL;
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no  = CK_FALSE;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;
	CK_MECHANISM dig_mec;
	/* 8 B */
	CK_BYTE key_des_value[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	/* 24 B */
	CK_BYTE key_des3_value[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	/* 32 B */
	CK_BYTE key_aes_value[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	CK_ATTRIBUTE templates[][11] = {
		{
			{CKA_LABEL,          "testkey DES 1",     13},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des,           sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des_value,       sizeof(key_des_value)}
		},
		{
			{CKA_LABEL,          "testkey DES 2",     13},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des,           sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des_value,       sizeof(key_des_value)}
		},
		{
			{CKA_LABEL,          "testkey DES 3",     13},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des,           sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des_value,       sizeof(key_des_value)}
		},
		{
			{CKA_LABEL,          "testkey DES 4",     13},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des,           sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des_value,       sizeof(key_des_value)}
		},
		{
			{CKA_LABEL,          "testkey DES3 1",    14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des3,          sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des3_value,      sizeof(key_des3_value)}
		},
		{
			{CKA_LABEL,          "testkey DES3 2",    14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des3,          sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des3_value,      sizeof(key_des3_value)}
		},
		{
			{CKA_LABEL,          "testkey DES3 3",    14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des3,          sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des3_value,      sizeof(key_des3_value)}
		},
		{
			{CKA_LABEL,          "testkey DES3 4",    14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_des3,          sizeof(type_des)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_des3_value,      sizeof(key_des3_value)}
		},
		{
			{CKA_LABEL,          "testkey AES 1",     14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_aes,           sizeof(type_aes)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_aes_value,       sizeof(key_aes_value)}
		},
		{
			{CKA_LABEL,          "testkey AES 2" ,    14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_aes,           sizeof(type_aes)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &no,                 sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_aes_value,       sizeof(key_aes_value)}
		},
		{
			{CKA_LABEL,          "testkey AES 3",     14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_aes,           sizeof(type_aes)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &yes,                sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_aes_value,       sizeof(key_aes_value)}
		},
		{
			{CKA_LABEL,          "testkey AES 4",     14},
			{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
			{CKA_KEY_TYPE,       &type_aes,           sizeof(type_aes)},
			{CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE,    &yes,                sizeof(CK_BBOOL)},
			{CKA_SENSITIVE,      &no,                 sizeof(CK_BBOOL)},
			{CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_DECRYPT,        &yes,                sizeof(CK_BBOOL)},
			{CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
			{CKA_UNWRAP,         &yes,                sizeof(CK_BBOOL)},
			{CKA_VALUE,          key_aes_value,       sizeof(key_aes_value)}
		},
	};
	CK_MECHANISM digest_mechanisms[] = {
		{CKM_MD5,       NULL_PTR, 0},
		{CKM_SHA_1,     NULL_PTR, 0},
		{CKM_SHA512,    NULL_PTR, 0}
	};
	/* 
	 * other mechanisms that can be used for digest, according to pkcs#11 v.2.40:
	 * SHA_224
	 * SHA_256
	 * SHA_384
	 * CKM_SEED_MAC                                   -> unsupported by openCryptoki
	 * CKM_GOSTR3411: input len: any, digest len: 32B -> unsupported by openCryptoki
	 * MD2 is not supported by the standard anymore (nor by openCryptoki)
	 */
	CK_ULONG digest_lens[] = {16, 20, 64};

	if(argc != 3) {
		die("Please provide a slot and a valid PIN");
	}
	pin = (CK_BYTE *) argv[2];
	initialize();
	slot = get_slot(atoi(argv[1]));
	session = start_session(slot);
	login(session, pin);
	CK_ULONG klen = 16;

	CK_MECHANISM gen_mec = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_ATTRIBUTE template[] = {
		{CKA_LABEL,          "testkey AES1",       12},
		{CKA_CLASS,          &class_secret,       sizeof(class_secret)},
		{CKA_KEY_TYPE,       &type_aes,           sizeof(type_aes)},
		// {CKA_TOKEN,          &yes,                sizeof(CK_BBOOL)},
		// {CKA_EXTRACTABLE,    &yes,                 sizeof(CK_BBOOL)},
		// {CKA_SENSITIVE,      &no,                sizeof(CK_BBOOL)},
		// {CKA_ENCRYPT,        &yes,                sizeof(CK_BBOOL)},
		// {CKA_DECRYPT,        &no,                sizeof(CK_BBOOL)},
		// {CKA_WRAP,           &yes,                sizeof(CK_BBOOL)},
		// {CKA_UNWRAP,         &no,                sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN,      &klen,              sizeof(klen)}
	};
	generate_key(session, &gen_mec, template, 4, &key);
	dig_mec = digest_mechanisms[1];
	digest_len = digest_lens[1];
	digest = malloc(digest_len * sizeof(CK_BYTE));
	digest_key(session, &dig_mec, key, &digest, &digest_len);
	show_hex(digest, digest_len);
	free(digest);


	for(int j=0; j<3; j++) {
		CK_MECHANISM dig_mec = digest_mechanisms[j];
		CK_ULONG digest_len = digest_lens[j];

		for(int i = 0; i<12; i++) {
			create_object(session, templates[i], 11, &key);

		 	digest = malloc(digest_len * sizeof(CK_BYTE));
			digest_key(session, &dig_mec, key, &digest, &digest_len);
			show_hex(digest, digest_len);
			free(digest);
		}
		printf("\n");
	}

	/* generate a pub/priv keypair */
	CK_OBJECT_HANDLE_PTR keys = create_key_pair(session);
	key = keys[1];

	/* use SHA1, but produces a CKR_KEY_INDIGESTIBLE error */
	dig_mec = digest_mechanisms[1];
	digest_len = digest_lens[1];
	digest = malloc(digest_len * sizeof(CK_BYTE));
	digest_key(session, &dig_mec, key, &digest, &digest_len);
	show_hex(digest, digest_len);
	free(digest);

	logout(session);
	end_session(session);
	finalize();

	return EXIT_SUCCESS;
}
