/*
 * Description: pkcs11_unix.h, platform specific macros needed by pcks11.h
 */

#ifndef PKCS11_UNIX_H
#define PKCS11_UNIX_H

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif /* PKCS11_UNIX_H */
