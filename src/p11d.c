/* See LICENSE file for copyright and license details. */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include "pkcs11_unix.h"
#include "utils.h"
#include "p11d.h"


char entry[4096];
CK_BYTE fingerprint_seed[] = {0xfe, 0xed, 0xca, 0x75, 0xda, 0xbb, 0xad, 0x00};
CK_LONG fingerprint_seed_len = sizeof(fingerprint_seed);


#if MODE == PERMISSIVE || MODE == ENFORCE

void init(void) __attribute__((constructor));
void end(void) __attribute__((destructor));

int sock;
char *socket_path = "/tmp/apilogger.sock";

void
init_sock() {
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sock == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
	/* [TODO] poll the socket until it gets ready, maybe? */
	if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		exit(EXIT_FAILURE);
	}
}

int
allow_operation(void) {
	// ssize_t t;
	// char c[1024];

	strcat(entry, "\n");
	if(send(sock, entry, strlen(entry), 0) == -1) {
		perror("send");
		exit(EXIT_FAILURE);
	}
	// t = recv(sock, &c, 1024, 0);
	// if(t > 0) {
	// 	if(c[0] != 'Y') {
	// 		if(MODE == ENFORCE) {
	// 			fprintf(stderr, "ERROR: Operation denied, aborting.\n");
	// 			fflush(stderr);
	// 			return 0;
	// 		} else {
	// 			fprintf(stderr, "WARNING: Dangerous operation detected.\n");
	// 			fflush(stderr);
	// 		}
	// 	}
	// } else if(t < 0) {
	// 	perror("recv");
	// } else {
	// 	fprintf(stderr, "server closed connection\n");
	// 	exit(EXIT_FAILURE);
	// }

	return 1;
}

/* called before main() */
void
init(void) {
	/* initialize random seed: */
	srand(time(NULL));
	init_sock();
}

/* called before quitting */
void
end(void) {
	close(sock);
}

#else /* MODE == DISABLED */

int
allow_operation(void) {
	printf("%s\n", entry);
	return 1;
}

#endif

void
set_rand_seed(void) {
	unsigned int i;

	for(i=0; i<fingerprint_seed_len; i++) {
		fingerprint_seed[i] = rand() % 256;
	}
}

void
strcat_repr_key(char *buf, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	char fingerprint[4096];
	unsigned int i, found_fingerprint, found_attr_fingerprint;
	orig_C_EncryptInit_f_type orig_C_EncryptInit;
	orig_C_Encrypt_f_type orig_C_Encrypt;
	orig_C_DecryptInit_f_type orig_C_DecryptInit;
	orig_C_Decrypt_f_type orig_C_Decrypt;
	orig_C_GetAttributeValue_f_type orig_C_GetAttributeValue;
	orig_C_SetAttributeValue_f_type orig_C_SetAttributeValue;
	orig_C_WrapKey_f_type orig_C_WrapKey;
	CK_RV rv;
	CK_MECHANISM enc_mec = {CKM_DES_ECB, NULL_PTR, 0};
	CK_BYTE_PTR data = NULL_PTR;
	CK_ULONG data_len = 0;
	CK_ULONG attr_count;
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL no = CK_FALSE;
	CK_ATTRIBUTE template[] = {
		{CKA_LABEL,       NULL_PTR, 0},
		{CKA_SENSITIVE,   NULL_PTR, 0},
		{CKA_ENCRYPT,     NULL_PTR, 0},
		{CKA_DECRYPT,     NULL_PTR, 0},
		{CKA_WRAP,        NULL_PTR, 0},
		{CKA_UNWRAP,      NULL_PTR, 0},
		{CKA_KEY_TYPE,    NULL_PTR, 0},
		{CKA_EXTRACTABLE, NULL_PTR, 0},
	};
	CK_ATTRIBUTE template_enable_encrypt[] = {
		{CKA_ENCRYPT,     &yes,     sizeof(CK_BBOOL)}
	};
	CK_ATTRIBUTE template_disable_encrypt[] = {
		{CKA_ENCRYPT,     &no,      sizeof(CK_BBOOL)}
	};

	char *attr_list[] = {
		"label",
		"sensitive",
		"encrypt",
		"decrypt",
		"wrap",
		"unwrap",
		"keytype",
		"extractable"
	};

	/* don't reuse wrapped functions, stick to the original ones to avoid infinite calls due to the wrapper */
	orig_C_GetAttributeValue = (orig_C_GetAttributeValue_f_type)dlsym(RTLD_NEXT, "C_GetAttributeValue");
	orig_C_EncryptInit = (orig_C_EncryptInit_f_type)dlsym(RTLD_NEXT, "C_EncryptInit");
	orig_C_Encrypt = (orig_C_Encrypt_f_type)dlsym(RTLD_NEXT, "C_Encrypt");
	orig_C_DecryptInit = (orig_C_DecryptInit_f_type)dlsym(RTLD_NEXT, "C_DecryptInit");
	orig_C_Decrypt = (orig_C_Decrypt_f_type)dlsym(RTLD_NEXT, "C_Decrypt");
	orig_C_SetAttributeValue = (orig_C_SetAttributeValue_f_type)dlsym(RTLD_NEXT, "C_SetAttributeValue");
	orig_C_WrapKey = (orig_C_WrapKey_f_type)dlsym(RTLD_NEXT, "C_WrapKey");
	/* reset the fingerprint string */
	memset(fingerprint, 0, sizeof(fingerprint));

	attr_count = 8;
	/* since pValue is NULL, the ulValueLen field is modified to hold the
	 * exact length of the specified attribute for the object */
	rv = orig_C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "[P11D] Get attribute value (sizes)");
	/* allocate memory for all the attributes found */
	for(i=0; i<attr_count; i++) {
		if(template[i].ulValueLen > 0) {
			template[i].pValue = malloc(template[i].ulValueLen);
		}
	}
	/* do another call to copy the attribute values into the buffer
	 * located at pValue  */
	rv = orig_C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "[P11D] Get attribute value");
	/* save the key handler */
	sprintf(&(buf[strlen(buf)]), "{\"handle\": \"%lu\", ", key);
	/* produce fingerprints based on key capabilities */
	found_fingerprint = 0;
	for(i=0; i<attr_count; i++) {
		found_attr_fingerprint = 1;
		sprintf(&(buf[strlen(buf)]), "\"%s\": ", attr_list[i]);
		/* if the specified attribute is not accessible or invalid the
		 * ulValueLen is modified to hold the value -1 (i.e., when it
		 * is cast to a CK_LONG, it holds -1). For this reason we cast
		 * ulValueLen to CK_LONG during the comparison */
		if((CK_LONG) template[i].ulValueLen < 1) {
			strcat(buf, "\"-\"");
		} else {
			strcat_repr_hex(buf, template[i].pValue, template[i].ulValueLen);

			/* randomize the seed */
			set_rand_seed();

			if(strcmp(attr_list[i], "encrypt") == 0 
			&& *((CK_BYTE_PTR) template[i].pValue) == CK_TRUE) {
				/* assume that at this point the attribute is always enabled */
				/* encrypt a seed value as an fingerprint of the key */
				rv = orig_C_EncryptInit(session, &enc_mec, key);
				check_ret(rv, "[P11D] Encrypt init");
				/* find the encrypted data len */
				rv = orig_C_Encrypt(session, fingerprint_seed, fingerprint_seed_len, NULL_PTR,
					&data_len);
				check_ret(rv, "[P11D] Encrypt (find len)");
				/* allocate the needed space */
				data = malloc(data_len * sizeof(CK_BYTE));
				/* perform the encrypt operation */
				rv = orig_C_Encrypt(session, fingerprint_seed, fingerprint_seed_len, data,
					&data_len);
				check_ret(rv, "[P11D] Encrypt");
			} else if(strcmp(attr_list[i], "decrypt") == 0
			&& *((CK_BYTE_PTR) template[i].pValue) == CK_TRUE) {
				/* assume that at this point the attribute is always enabled */
				/* decrypt a seed value as an fingerprint of the key */
				rv = orig_C_DecryptInit(session, &enc_mec, key);
				check_ret(rv, "[P11D] Decrypt init");
				/* find the encrypted data len */
				rv = orig_C_Decrypt(session, fingerprint_seed, fingerprint_seed_len, NULL_PTR,
					&data_len);
				check_ret(rv, "[P11D] Decrypt (find len)");
				/* allocate the needed space */
				data = malloc(data_len * sizeof(CK_BYTE));
				/* perform the encrypt operation */
				rv = orig_C_Decrypt(session, fingerprint_seed, fingerprint_seed_len, data,
					&data_len);
				check_ret(rv, "[P11D] Decrypt");
			} else if(strcmp(attr_list[i], "wrap") == 0 
			&& *((CK_BYTE_PTR) template[i].pValue) == CK_TRUE) {
				/* wrap a key with itself */
				rv = orig_C_WrapKey(session, &enc_mec, key, key, NULL_PTR, &data_len);
				check_ret(rv, "[P11D] Wrap key (find len)");
				data = malloc(data_len * sizeof(CK_BYTE));
				rv = orig_C_WrapKey(session, &enc_mec, key, key, data, &data_len);
				check_ret(rv, "[P11D] Wrap key (set value)");
			} else {
				/* during this iteration it was not possible to procude a fingerprint 
				 * with the actual attribute */
				found_attr_fingerprint = 0;
			}
			if(found_attr_fingerprint) {
				/* update the global fingerprint found flag */
				found_fingerprint = 1;
				/* assume that data is always defined here */
				/* let f be the fingerprint function, the format is "<f>": ("x", "f(x)") */
				sprintf(&(fingerprint[strlen(fingerprint)]), "\"%s\": [", attr_list[i]);
				strcat_repr_hex(fingerprint, fingerprint_seed, fingerprint_seed_len);
				strcat(fingerprint, ", ");
				strcat_repr_hex(fingerprint, data, data_len);
				free(data);
				strcat(fingerprint, "], ");
			}
		}
		strcat(buf, ", ");
	}
	if(!found_fingerprint) {
		/* all the attributes are disabled, we temporarily enable the encrypt 
		 * attribute to compute the fingerprint */
		set_rand_seed();
		rv = orig_C_SetAttributeValue(session, key, template_enable_encrypt, 1);
		check_ret(rv, "[P11D] Set attribute value (enable encrypt)");
		rv = orig_C_EncryptInit(session, &enc_mec, key);
		check_ret(rv, "[P11D] Encrypt init");
		/* find the encrypted data len */
		rv = orig_C_Encrypt(session, fingerprint_seed, fingerprint_seed_len, NULL_PTR,
			&data_len);
		check_ret(rv, "[P11D] Encrypt (find len)");
		/* allocate the needed space */
		data = malloc(data_len * sizeof(CK_BYTE));
		/* perform the encrypt operation */
		rv = orig_C_Encrypt(session, fingerprint_seed, fingerprint_seed_len, data,
			&data_len);
		check_ret(rv, "[P11D] Encrypt");
		rv = orig_C_SetAttributeValue(session, key, template_disable_encrypt, 1);
		check_ret(rv, "[P11D] Set attribute value (disable encrypt)");
		sprintf(&(fingerprint[strlen(fingerprint)]), "\"%s\": [", "encrypt");
		/* assume that data is always defined here */
		/* let f be the fingerprint function, the format is "<f>": ("x", "f(x)") */
		strcat_repr_hex(fingerprint, fingerprint_seed, fingerprint_seed_len);
		strcat(fingerprint, ", ");
		strcat_repr_hex(fingerprint, data, data_len);
		free(data);
		strcat(fingerprint, "], ");
	}

	strcat(buf, "\"fingerprint\": {");
	strcat(buf, fingerprint);
	strcat(buf, "}}");
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
	orig_C_Initialize_f_type orig_C_Initialize;
	orig_C_Initialize = (orig_C_Initialize_f_type)dlsym(RTLD_NEXT, "C_Initialize");
	return orig_C_Initialize(pInitArgs);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
	orig_C_Finalize_f_type orig_C_Finalize;
	orig_C_Finalize = (orig_C_Finalize_f_type)dlsym(RTLD_NEXT, "C_Finalize");
	return orig_C_Finalize(pReserved);
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
	orig_C_GetInfo_f_type orig_C_GetInfo;
	orig_C_GetInfo = (orig_C_GetInfo_f_type)dlsym(RTLD_NEXT, "C_GetInfo");
	return orig_C_GetInfo(pInfo);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	orig_C_GetFunctionList_f_type orig_C_GetFunctionList;
	orig_C_GetFunctionList = (orig_C_GetFunctionList_f_type)dlsym(RTLD_NEXT, "C_GetFunctionList");
	return orig_C_GetFunctionList(ppFunctionList);
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	orig_C_GetSlotList_f_type orig_C_GetSlotList;
	orig_C_GetSlotList = (orig_C_GetSlotList_f_type)dlsym(RTLD_NEXT, "C_GetSlotList");
	return orig_C_GetSlotList(tokenPresent, pSlotList, pulCount);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
	orig_C_GetSlotInfo_f_type orig_C_GetSlotInfo;
	orig_C_GetSlotInfo = (orig_C_GetSlotInfo_f_type)dlsym(RTLD_NEXT, "C_GetSlotInfo");
	return orig_C_GetSlotInfo(slotID, pInfo);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
	orig_C_GetTokenInfo_f_type orig_C_GetTokenInfo;
	orig_C_GetTokenInfo = (orig_C_GetTokenInfo_f_type)dlsym(RTLD_NEXT, "C_GetTokenInfo");
	return orig_C_GetTokenInfo(slotID, pInfo);
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
	orig_C_GetMechanismList_f_type orig_C_GetMechanismList;
	orig_C_GetMechanismList = (orig_C_GetMechanismList_f_type)dlsym(RTLD_NEXT, "C_GetMechanismList");
	return orig_C_GetMechanismList(slotID, pMechanismList, pulCount);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
	orig_C_GetMechanismInfo_f_type orig_C_GetMechanismInfo;
	orig_C_GetMechanismInfo = (orig_C_GetMechanismInfo_f_type)dlsym(RTLD_NEXT, "C_GetMechanismInfo");
	return orig_C_GetMechanismInfo(slotID, type, pInfo);
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
	orig_C_InitToken_f_type orig_C_InitToken;
	orig_C_InitToken = (orig_C_InitToken_f_type)dlsym(RTLD_NEXT, "C_InitToken");
	return orig_C_InitToken(slotID, pPin, ulPinLen, pLabel);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	orig_C_InitPIN_f_type orig_C_InitPIN;
	orig_C_InitPIN = (orig_C_InitPIN_f_type)dlsym(RTLD_NEXT, "C_InitPIN");
	return orig_C_InitPIN(hSession, pPin, ulPinLen);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
	orig_C_SetPIN_f_type orig_C_SetPIN;
	orig_C_SetPIN = (orig_C_SetPIN_f_type)dlsym(RTLD_NEXT, "C_SetPIN");
	return orig_C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
	orig_C_OpenSession_f_type orig_C_OpenSession;
	orig_C_OpenSession = (orig_C_OpenSession_f_type)dlsym(RTLD_NEXT, "C_OpenSession");
	return orig_C_OpenSession(slotID, flags, pApplication, Notify, phSession);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
	orig_C_CloseSession_f_type orig_C_CloseSession;
	orig_C_CloseSession = (orig_C_CloseSession_f_type)dlsym(RTLD_NEXT, "C_CloseSession");
	return orig_C_CloseSession(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
	orig_C_CloseAllSessions_f_type orig_C_CloseAllSessions;
	orig_C_CloseAllSessions = (orig_C_CloseAllSessions_f_type)dlsym(RTLD_NEXT, "C_CloseAllSessions");
	return orig_C_CloseAllSessions(slotID);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
	orig_C_GetSessionInfo_f_type orig_C_GetSessionInfo;
	orig_C_GetSessionInfo = (orig_C_GetSessionInfo_f_type)dlsym(RTLD_NEXT, "C_GetSessionInfo");
	return orig_C_GetSessionInfo(hSession, pInfo);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
	orig_C_GetOperationState_f_type orig_C_GetOperationState;
	orig_C_GetOperationState = (orig_C_GetOperationState_f_type)dlsym(RTLD_NEXT, "C_GetOperationState");
	return orig_C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
	orig_C_SetOperationState_f_type orig_C_SetOperationState;
	orig_C_SetOperationState = (orig_C_SetOperationState_f_type)dlsym(RTLD_NEXT, "C_SetOperationState");
	return orig_C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}

int
is_sensitive(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
	CK_RV rv;
	orig_C_GetAttributeValue_f_type orig_C_GetAttributeValue;
	CK_ATTRIBUTE template[] = {
		{CKA_SENSITIVE,   NULL_PTR, 0},
		{CKA_EXTRACTABLE, NULL_PTR, 0},
	};
	char *attr_list[] = {
		"sensitive",
		"extractable"
	};
	unsigned int i, key_is_sensitive = 0;
	CK_ULONG attr_count = 2;

	orig_C_GetAttributeValue = (orig_C_GetAttributeValue_f_type)dlsym(RTLD_NEXT, "C_GetAttributeValue");	
	/* since pValue is NULL, the ulValueLen field is modified to hold the
	 * exact length of the specified attribute for the object */
	rv = orig_C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "[P11D] Get attribute value (sizes)");
	/* allocate memory for all the attributes found */
	for(i=0; i<attr_count; i++) {
		if(template[i].ulValueLen > 0) {
			template[i].pValue = malloc(template[i].ulValueLen);
		}
	}
	/* do another call to copy the attribute values into the buffer
	 * located at pValue  */
	rv = orig_C_GetAttributeValue(session, key, template, attr_count);
	check_ret(rv, "[P11D] Get attribute value");
	for(i=0; i<attr_count; i++) {
		if(strcmp(attr_list[i], "sensitive") == 0 && *((CK_BYTE_PTR) template[i].pValue) == CK_TRUE) {
			key_is_sensitive = 1;
		} else if(strcmp(attr_list[i], "extractable") == 0 && *((CK_BYTE_PTR) template[i].pValue) == CK_FALSE) {
			key_is_sensitive = 1;
		}
		free(template[i].pValue);
	}

	return key_is_sensitive;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
	CK_RV rv, orig_rv;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object;
	orig_C_Login_f_type orig_C_Login;
	CK_ATTRIBUTE_PTR template_empty = NULL;
	unsigned int object_counter = 0;

	orig_C_Login = (orig_C_Login_f_type)dlsym(RTLD_NEXT, "C_Login");

	orig_rv = orig_C_Login(hSession, userType, pPin, ulPinLen);
	if(orig_rv == CKR_OK) {
		memset(entry, 0, sizeof(entry));
		strcat(entry, "[\"C_Login\", [");
		/* dump all the keys found in the token */
		rv = C_FindObjectsInit(hSession, template_empty, 0);
		check_ret(rv, "[P11D] Find Objects Init");
		/* search for keys that match a template, one at a time */
		rv = C_FindObjects(hSession, &object, 1, &object_count);
		check_ret(rv, "[P11D] Find Objects");
		while(object_count > 0) {
			/* only list this key if it is either sensitive or non extractable */
			if(is_sensitive(hSession, object)) {
				strcat_repr_key(entry, hSession, object);
				strcat(entry, ", ");
				rv = C_FindObjects(hSession, &object, 1, &object_count);
				check_ret(rv, "[P11D] Find Objects");
			}
			object_counter++;
		}
		rv = C_FindObjectsFinal(hSession);
		check_ret(rv, "[P11D] Find Objects Final");
		strcat(entry, "]]");
		allow_operation();
	}

	return orig_rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
	CK_RV rv;
	orig_C_Logout_f_type orig_C_Logout;
	orig_C_Logout = (orig_C_Logout_f_type)dlsym(RTLD_NEXT, "C_Logout");

	rv = orig_C_Logout(hSession);
	if(rv == CKR_OK) {
		memset(entry, 0, sizeof(entry));
		strcat(entry, "END");
		allow_operation();
	}

	return rv;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
	CK_RV rv;
	orig_C_CreateObject_f_type orig_C_CreateObject;
	orig_C_CreateObject = (orig_C_CreateObject_f_type)dlsym(RTLD_NEXT, "C_CreateObject");

	rv = orig_C_CreateObject(hSession, pTemplate, ulCount, phObject);
	if(rv == CKR_OK) {
		memset(entry, 0, sizeof(entry));
		strcat(entry, "[\"C_CreateObject\", [");
		strcat_repr_key(entry, hSession, *phObject);
		strcat(entry, "]]");
		allow_operation();
	}

	return rv;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
	orig_C_CopyObject_f_type orig_C_CopyObject;
	orig_C_CopyObject = (orig_C_CopyObject_f_type)dlsym(RTLD_NEXT, "C_CopyObject");
	return orig_C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
	orig_C_DestroyObject_f_type orig_C_DestroyObject;
	orig_C_DestroyObject = (orig_C_DestroyObject_f_type)dlsym(RTLD_NEXT, "C_DestroyObject");
	return orig_C_DestroyObject(hSession, hObject);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
	orig_C_GetObjectSize_f_type orig_C_GetObjectSize;
	orig_C_GetObjectSize = (orig_C_GetObjectSize_f_type)dlsym(RTLD_NEXT, "C_GetObjectSize");
	return orig_C_GetObjectSize(hSession, hObject, pulSize);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	orig_C_GetAttributeValue_f_type orig_C_GetAttributeValue;
	orig_C_GetAttributeValue = (orig_C_GetAttributeValue_f_type)dlsym(RTLD_NEXT, "C_GetAttributeValue");
	return orig_C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	orig_C_SetAttributeValue_f_type orig_C_SetAttributeValue;
	orig_C_SetAttributeValue = (orig_C_SetAttributeValue_f_type)dlsym(RTLD_NEXT, "C_SetAttributeValue");
	return orig_C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	orig_C_FindObjectsInit_f_type orig_C_FindObjectsInit;
	orig_C_FindObjectsInit = (orig_C_FindObjectsInit_f_type)dlsym(RTLD_NEXT, "C_FindObjectsInit");
	return orig_C_FindObjectsInit(hSession, pTemplate, ulCount);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
	orig_C_FindObjects_f_type orig_C_FindObjects;
	orig_C_FindObjects = (orig_C_FindObjects_f_type)dlsym(RTLD_NEXT, "C_FindObjects");
	return orig_C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
	orig_C_FindObjectsFinal_f_type orig_C_FindObjectsFinal;
	orig_C_FindObjectsFinal = (orig_C_FindObjectsFinal_f_type)dlsym(RTLD_NEXT, "C_FindObjectsFinal");
	return orig_C_FindObjectsFinal(hSession);
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CK_RV rv;
	orig_C_EncryptInit_f_type orig_C_EncryptInit;
	orig_C_EncryptInit = (orig_C_EncryptInit_f_type)dlsym(RTLD_NEXT, "C_EncryptInit");

	// memset(entry, 0, sizeof(entry));
	// strcat(entry, "[\"C_EncryptInit\", [");
	// strcat_repr_key(entry, hSession, hKey);
	// strcat(entry, "]]");

	rv = orig_C_EncryptInit(hSession, pMechanism, hKey);
	if(rv == CKR_OK) {
		// allow_operation();
	}

	return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
	CK_RV rv;
	orig_C_Encrypt_f_type orig_C_Encrypt;
	orig_C_Encrypt = (orig_C_Encrypt_f_type)dlsym(RTLD_NEXT, "C_Encrypt");

	rv = orig_C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	/* do not interfere with the dummy allocation operation */
	if(rv == CKR_OK && pEncryptedData != NULL_PTR) {
		/* reset the entry array before concatenating strings */
		// memset(entry, 0, sizeof(entry));
		// strcat(entry, "[\"C_Encrypt\", [");
		// strcat_repr_hex(entry, pData, ulDataLen);
		// strcat(entry, ", ");
		// strcat_repr_hex(entry, pEncryptedData, *pulEncryptedDataLen);
		// strcat(entry, "]]");
		// allow_operation();
	}

	return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	orig_C_EncryptUpdate_f_type orig_C_EncryptUpdate;
	orig_C_EncryptUpdate = (orig_C_EncryptUpdate_f_type)dlsym(RTLD_NEXT, "C_EncryptUpdate");
	return orig_C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
	orig_C_EncryptFinal_f_type orig_C_EncryptFinal;
	orig_C_EncryptFinal = (orig_C_EncryptFinal_f_type)dlsym(RTLD_NEXT, "C_EncryptFinal");
	return orig_C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	CK_RV rv;
	orig_C_DecryptInit_f_type orig_C_DecryptInit;
	orig_C_DecryptInit = (orig_C_DecryptInit_f_type)dlsym(RTLD_NEXT, "C_DecryptInit");

	// memset(entry, 0, sizeof(entry));
	// strcat(entry, "[\"C_DecryptInit\", [");
	// strcat_repr_key(entry, hSession, hKey);
	// strcat(entry, "]]");

	rv = orig_C_DecryptInit(hSession, pMechanism, hKey);
	if(rv == CKR_OK) {
		/* reset the entry array before concatenating strings */
		memset(entry, 0, sizeof(entry));
		/* ["C_Decrypt", ["<hKey>"], ... */
		sprintf(entry, "[\"C_Decrypt\", [\"%lu\"], ", hKey);
		// allow_operation();
	}

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
	CK_RV rv;
	orig_C_Decrypt_f_type orig_C_Decrypt;
	orig_C_Decrypt = (orig_C_Decrypt_f_type)dlsym(RTLD_NEXT, "C_Decrypt");

	rv = orig_C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	/* do not interfere with the dummy allocation operation */
	if(rv == CKR_OK && pData != NULL_PTR) {
		/* continue from orig_C_DecryptInit: ["C_Decrypt", ["<hKey>"], "<ret>"] */
		strcat_repr_hex(entry, pData, *pulDataLen);
		strcat(entry, "]");
		allow_operation();

		// /* reset the entry array before concatenating strings */
		// memset(entry, 0, sizeof(entry));
		// strcat(entry, "[\"C_Decrypt\", [");
		// strcat_repr_hex(entry, pEncryptedData, ulEncryptedDataLen);
		// strcat(entry, ", ");
		// strcat_repr_hex(entry, pData, *pulDataLen);
		// strcat(entry, "]]");
		// allow_operation();
	}

	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	orig_C_DecryptUpdate_f_type orig_C_DecryptUpdate;
	orig_C_DecryptUpdate = (orig_C_DecryptUpdate_f_type)dlsym(RTLD_NEXT, "C_DecryptUpdate");
	return orig_C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
	orig_C_DecryptFinal_f_type orig_C_DecryptFinal;
	orig_C_DecryptFinal = (orig_C_DecryptFinal_f_type)dlsym(RTLD_NEXT, "C_DecryptFinal");
	return orig_C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
	orig_C_DigestInit_f_type orig_C_DigestInit;
	orig_C_DigestInit = (orig_C_DigestInit_f_type)dlsym(RTLD_NEXT, "C_DigestInit");
	return orig_C_DigestInit(hSession, pMechanism);
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
	orig_C_Digest_f_type orig_C_Digest;
	orig_C_Digest = (orig_C_Digest_f_type)dlsym(RTLD_NEXT, "C_Digest");
	return orig_C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	orig_C_DigestUpdate_f_type orig_C_DigestUpdate;
	orig_C_DigestUpdate = (orig_C_DigestUpdate_f_type)dlsym(RTLD_NEXT, "C_DigestUpdate");
	return orig_C_DigestUpdate(hSession, pPart, ulPartLen);
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
	orig_C_DigestKey_f_type orig_C_DigestKey;
	orig_C_DigestKey = (orig_C_DigestKey_f_type)dlsym(RTLD_NEXT, "C_DigestKey");
	return orig_C_DigestKey(hSession, hKey);
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
	orig_C_DigestFinal_f_type orig_C_DigestFinal;
	orig_C_DigestFinal = (orig_C_DigestFinal_f_type)dlsym(RTLD_NEXT, "C_DigestFinal");
	return orig_C_DigestFinal(hSession, pDigest, pulDigestLen);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	orig_C_SignInit_f_type orig_C_SignInit;
	orig_C_SignInit = (orig_C_SignInit_f_type)dlsym(RTLD_NEXT, "C_SignInit");
	return orig_C_SignInit(hSession, pMechanism, hKey);
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	orig_C_Sign_f_type orig_C_Sign;
	orig_C_Sign = (orig_C_Sign_f_type)dlsym(RTLD_NEXT, "C_Sign");
	return orig_C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	orig_C_SignUpdate_f_type orig_C_SignUpdate;
	orig_C_SignUpdate = (orig_C_SignUpdate_f_type)dlsym(RTLD_NEXT, "C_SignUpdate");
	return orig_C_SignUpdate(hSession, pPart, ulPartLen);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	orig_C_SignFinal_f_type orig_C_SignFinal;
	orig_C_SignFinal = (orig_C_SignFinal_f_type)dlsym(RTLD_NEXT, "C_SignFinal");
	return orig_C_SignFinal(hSession, pSignature, pulSignatureLen);
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	orig_C_SignRecoverInit_f_type orig_C_SignRecoverInit;
	orig_C_SignRecoverInit = (orig_C_SignRecoverInit_f_type)dlsym(RTLD_NEXT, "C_SignRecoverInit");
	return orig_C_SignRecoverInit(hSession, pMechanism, hKey);
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	orig_C_SignRecover_f_type orig_C_SignRecover;
	orig_C_SignRecover = (orig_C_SignRecover_f_type)dlsym(RTLD_NEXT, "C_SignRecover");
	return orig_C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	orig_C_VerifyInit_f_type orig_C_VerifyInit;
	orig_C_VerifyInit = (orig_C_VerifyInit_f_type)dlsym(RTLD_NEXT, "C_VerifyInit");
	return orig_C_VerifyInit(hSession, pMechanism, hKey);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
	orig_C_Verify_f_type orig_C_Verify;
	orig_C_Verify = (orig_C_Verify_f_type)dlsym(RTLD_NEXT, "C_Verify");
	return orig_C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
	orig_C_VerifyUpdate_f_type orig_C_VerifyUpdate;
	orig_C_VerifyUpdate = (orig_C_VerifyUpdate_f_type)dlsym(RTLD_NEXT, "C_VerifyUpdate");
	return orig_C_VerifyUpdate(hSession, pPart, ulPartLen);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
	orig_C_VerifyFinal_f_type orig_C_VerifyFinal;
	orig_C_VerifyFinal = (orig_C_VerifyFinal_f_type)dlsym(RTLD_NEXT, "C_VerifyFinal");
	return orig_C_VerifyFinal(hSession, pSignature, ulSignatureLen);
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
	orig_C_VerifyRecoverInit_f_type orig_C_VerifyRecoverInit;
	orig_C_VerifyRecoverInit = (orig_C_VerifyRecoverInit_f_type)dlsym(RTLD_NEXT, "C_VerifyRecoverInit");
	return orig_C_VerifyRecoverInit(hSession, pMechanism, hKey);
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
	orig_C_VerifyRecover_f_type orig_C_VerifyRecover;
	orig_C_VerifyRecover = (orig_C_VerifyRecover_f_type)dlsym(RTLD_NEXT, "C_VerifyRecover");
	return orig_C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	orig_C_DigestEncryptUpdate_f_type orig_C_DigestEncryptUpdate;
	orig_C_DigestEncryptUpdate = (orig_C_DigestEncryptUpdate_f_type)dlsym(RTLD_NEXT, "C_DigestEncryptUpdate");
	return orig_C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	orig_C_DecryptDigestUpdate_f_type orig_C_DecryptDigestUpdate;
	orig_C_DecryptDigestUpdate = (orig_C_DecryptDigestUpdate_f_type)dlsym(RTLD_NEXT, "C_DecryptDigestUpdate");
	return orig_C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
	orig_C_SignEncryptUpdate_f_type orig_C_SignEncryptUpdate;
	orig_C_SignEncryptUpdate = (orig_C_SignEncryptUpdate_f_type)dlsym(RTLD_NEXT, "C_SignEncryptUpdate");
	return orig_C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
	orig_C_DecryptVerifyUpdate_f_type orig_C_DecryptVerifyUpdate;
	orig_C_DecryptVerifyUpdate = (orig_C_DecryptVerifyUpdate_f_type)dlsym(RTLD_NEXT, "C_DecryptVerifyUpdate");
	return orig_C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
	CK_RV rv;
	orig_C_GenerateKey_f_type orig_C_GenerateKey;
	orig_C_GenerateKey = (orig_C_GenerateKey_f_type)dlsym(RTLD_NEXT, "C_GenerateKey");

	/* reset the entry array before concatenating strings */
	rv = orig_C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	if(rv == CKR_OK) {
		memset(entry, 0, sizeof(entry));
		strcat(entry, "[\"C_GenerateKey\", [");
		strcat_repr_key(entry, hSession, *phKey);
		strcat(entry, "]]");
		allow_operation();
	}

	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
	orig_C_GenerateKeyPair_f_type orig_C_GenerateKeyPair;
	orig_C_GenerateKeyPair = (orig_C_GenerateKeyPair_f_type)dlsym(RTLD_NEXT, "C_GenerateKeyPair");
	return orig_C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
	CK_RV rv;
	orig_C_WrapKey_f_type orig_C_WrapKey;
	orig_C_WrapKey = (orig_C_WrapKey_f_type)dlsym(RTLD_NEXT, "C_WrapKey");

	rv = orig_C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	/* do not interfere with the dummy allocation operation */
	if(rv == CKR_OK && pWrappedKey != NULL_PTR) {
		/* reset the entry array before concatenating strings */
		memset(entry, 0, sizeof(entry));
		/* ["C_WrapKey", ["<hWrappingKey>", "<hWrappedKey">]] */
		sprintf(entry, "[\"C_WrapKey\", [\"%lu\", \"%lu\"]]", hWrappingKey, hKey);
		allow_operation();

		/* reset the entry array before concatenating strings */
		// memset(entry, 0, sizeof(entry));
		// strcat(entry, "[\"C_WrapKey\", [");
		// strcat_repr_key(entry, hSession, hWrappingKey);
		// strcat(entry, ", ");
		// strcat_repr_key(entry, hSession, hKey);
		// strcat(entry, ", ");
		// strcat_repr_hex(entry, pWrappedKey, *pulWrappedKeyLen);
		// strcat(entry, "]]");
		// allow_operation();
	}

	return rv;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	CK_RV rv;
	orig_C_UnwrapKey_f_type orig_C_UnwrapKey;
	orig_C_UnwrapKey = (orig_C_UnwrapKey_f_type)dlsym(RTLD_NEXT, "C_UnwrapKey");

	rv = orig_C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
	if(rv == CKR_OK) {
		/* reset the entry array before concatenating strings */
		memset(entry, 0, sizeof(entry));
		strcat(entry, "[\"C_UnwrapKey\", [");
		strcat_repr_key(entry, hSession, hUnwrappingKey);
		strcat(entry, ", ");
		strcat_repr_hex(entry, pWrappedKey, ulWrappedKeyLen);
		strcat(entry, ", ");
		strcat_repr_key(entry, hSession, *phKey);
		strcat(entry, "]]");
		allow_operation();
	}

	return rv;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
	orig_C_DeriveKey_f_type orig_C_DeriveKey;
	orig_C_DeriveKey = (orig_C_DeriveKey_f_type)dlsym(RTLD_NEXT, "C_DeriveKey");
	return orig_C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
	orig_C_SeedRandom_f_type orig_C_SeedRandom;
	orig_C_SeedRandom = (orig_C_SeedRandom_f_type)dlsym(RTLD_NEXT, "C_SeedRandom");
	return orig_C_SeedRandom(hSession, pSeed, ulSeedLen);
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) {
	orig_C_GenerateRandom_f_type orig_C_GenerateRandom;
	orig_C_GenerateRandom = (orig_C_GenerateRandom_f_type)dlsym(RTLD_NEXT, "C_GenerateRandom");
	return orig_C_GenerateRandom(hSession, RandomData, ulRandomLen);
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
	orig_C_GetFunctionStatus_f_type orig_C_GetFunctionStatus;
	orig_C_GetFunctionStatus = (orig_C_GetFunctionStatus_f_type)dlsym(RTLD_NEXT, "C_GetFunctionStatus");
	return orig_C_GetFunctionStatus(hSession);
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
	orig_C_CancelFunction_f_type orig_C_CancelFunction;
	orig_C_CancelFunction = (orig_C_CancelFunction_f_type)dlsym(RTLD_NEXT, "C_CancelFunction");
	return orig_C_CancelFunction(hSession);
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved) {
	orig_C_WaitForSlotEvent_f_type orig_C_WaitForSlotEvent;
	orig_C_WaitForSlotEvent = (orig_C_WaitForSlotEvent_f_type)dlsym(RTLD_NEXT, "C_WaitForSlotEvent");
	return orig_C_WaitForSlotEvent(flags, pSlot, pRserved);
}
