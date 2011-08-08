#include "stdafx.h"
#include "DlogGroup.h"
#include "Utils.h"
#include "cryptlib.h"
#include "gfpcrypt.h"

using namespace CryptoPP;

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_createDlogZp
  (JNIEnv *env, jobject, jbyteArray p, jlong element){
	  Utils utils;

	  //convert to Integer
	  Integer integerP = utils.jbyteArrayToCryptoPPInteger(env, p);

	  DL_GroupParameters_GFP * group = new DL_GroupParameters_GFP();
	  group->Initialize(integerP,  *(Integer*) element);

	  return (jlong) group;
}


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_inverseElement
  (JNIEnv *, jobject, jlong group, jlong element){
	  Utils utils;

	  Integer mod = ((DL_GroupParameters_GFP*) group)->GetModulus();
	  ModularArithmetic ma(mod);
	  Integer result = ma.MultiplicativeInverse( *(Integer*)element);

	  return (jlong)utils.getPointerToInteger(result);
}


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_exponentiateElement
  (JNIEnv *env, jobject, jlong group, jlong element, jbyteArray exponent){
	   Utils utils;

	  //convert the exponent to Integer
	  Integer integerExp = utils.jbyteArrayToCryptoPPInteger(env, exponent);

	  //exponentiate the element
	  Integer result = ((DL_GroupParameters_GFP*) group)->ExponentiateElement(*(Integer*) element, integerExp);

	  //get pointer to the result and return it
	  Integer* resultP = utils.getPointerToInteger(result);
	  return (jlong)resultP;
}


JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_multiplyElements
  (JNIEnv *, jobject, jlong group, jlong element1, jlong element2){
	  Utils utils;

	  //multiply the element
	  Integer result = ((DL_GroupParameters_GFP*) group)->MultiplyElements(*(Integer*) element1, *(Integer*) element2);

	  //get pointer to the result and return it
	  Integer* resultP = utils.getPointerToInteger(result);
	  return (jlong)resultP;
}


JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_deleteDlogZp
  (JNIEnv *, jobject, jlong groupPtr){
	  //free the allocated memory
	  delete((void*) groupPtr);
}