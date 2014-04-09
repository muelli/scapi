/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC */

#ifndef _Included_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
#define _Included_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    createHMAC
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_createHMAC
  (JNIEnv *, jobject, jstring);

/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    setKey
 * Signature: (JLjava/lang/String;[B)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_setKey
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    getNativeBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_getNativeBlockSize
  (JNIEnv *, jobject, jlong);

JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_getName
  (JNIEnv *, jobject, jlong);
/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    updateNative
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_updateNative
  (JNIEnv *, jobject, jlong, jbyteArray, jint, jint);

/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    updateFinal
 * Signature: (J[BI)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_updateFinal
  (JNIEnv *, jobject, jlong, jbyteArray, jint);

/*
 * Class:     edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC
 * Method:    deleteNative
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_prf_openSSL_OpenSSLHMAC_deleteNative
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif