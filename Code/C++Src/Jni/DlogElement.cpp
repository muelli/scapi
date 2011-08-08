#include "stdafx.h"
#include "DlogElement.h"
#include "Utils.h"
#include "Integer.h";


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpElementCryptoPp_getPointerToElement
  (JNIEnv *env, jobject, jbyteArray element){
	  Utils utils;

	  //convert to Integer and get pointer to it
	  Integer* pointerToEl = utils.jbyteArrayToCryptoPPIntegerPointer(env, element);

	  //return the pointer
	  return (jlong) pointerToEl;
}

JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpElementCryptoPp_getElement
  (JNIEnv *env, jobject, jlong element){
	  Utils utils;

	  //convert to jbyteArray and return it
	  return utils.CryptoPPIntegerTojbyteArray(env, *((Integer*)element));
}

JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_ZpElementCryptoPp_deleteElement
  (JNIEnv *, jobject, jlong elPtr){
	   //free the allocated memory
	  delete((void*) elPtr);
}