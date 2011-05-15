#include <stdio.h>
#include "stdafx.h"
#include "jni.h" 
#include <string>
#include "TrapdoorPermutation.h"
#include "rabin.h"
#include "rsa.h"
#include "cryptlib.h"
#include "Utils.h"
#include "osrng.h"

using namespace std;
using namespace CryptoPP;

/*
 * function createTP : This function creates a trapdoor permutation and returns a pointer to the created object.  
 * param tpName	     : The name of the trapdoor permutation we wish to create
 * return			 : A pointer to the created trapdoor permutation.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpTrapdoorPermutation_createTP
  (JNIEnv *env, jobject, jstring tpName) {

	TrapdoorFunction *tpPtr = NULL;

	//get the string from java
	const char* str = env->GetStringUTFChars(tpName, NULL);

	//supports all of the trapdoor permutations. Get the name of the required permutation and instanciate that.
	if(strcmp (str,"RSA") == 0)
		tpPtr = new InvertibleRSAFunction;
	else if(strcmp (str,"Rabin") == 0)
		tpPtr = new InvertibleRabinFunction;
	

	//return a pointer to the created hash.
	return (jlong)tpPtr;
}

/*
 * function loadRSAName : This function return the name of the RSA trapdoor permutation
 * param ptr	        : The pointer to the RSA object 
 * return			    : The name of the trapdoor permutation.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpRSAPermutation_loadRSAName
  (JNIEnv *env, jobject, jlong ptr) {

	  string ls =((RSA *) ptr) -> StaticAlgorithmName();
	  return env->NewStringUTF(ls.c_str());
}

/*
 * function loadRabinName : This function return the name of the Rabin trapdoor permutation
 * param ptr	          : The pointer to the Rabin object 
 * return			      : The name of the trapdoor permutation.
 */
JNIEXPORT jstring JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpRabinPermutation_loadRabinName
  (JNIEnv *env, jobject, jlong ptr) {

	  string ls =((Rabin *) ptr) -> StaticAlgorithmName();
	  return env->NewStringUTF(ls.c_str());
}

/*
 * function initRSA : This function initialize the RSA object
 * param tpPtr	    : The pointer to the trapdoor permutation object 
 * param modolus	: modolus (n)
 * param pubExp	    : pubic exponent (e)
 * param privExp	: private exponent (d)
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpRSAPermutation_initRSA
  (JNIEnv *env, jobject, jlong ptr, jbyteArray modolus, jbyteArray pubExp, jbyteArray privExp) {
	  Integer n, e, d;
	  Utils utils;

	  n = utils.byteArrToInteger(env, modolus);
	  e = utils.byteArrToInteger(env, pubExp);
	  d = utils.byteArrToInteger(env, privExp);

	  ((InvertibleRSAFunction *) ptr) -> Initialize(n, e, d);
}

/*
 * 
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpTrapdoorPermutation_computeTP
  (JNIEnv *env, jobject, jlong ptr, jbyteArray element) {
	  
	  Utils utils;
	  Integer x = utils.byteArrToInteger(env, element);
	  Integer result = ((TrapdoorFunction *) ptr)-> ApplyFunction(x);
	  return utils.integerToByteArr(env, result);
}

/*
 * 
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpTrapdoorPermutation_invertTP
  (JNIEnv *env, jobject, jlong ptr, jbyteArray element) {
	  Utils utils;
	  Integer x = utils.byteArrToInteger(env, element);

	  // Pseudo Random Number Generator
	  AutoSeededRandomPool rng;
	  Integer result = ((TrapdoorFunctionInverse *) ptr)-> CalculateInverse(rng, x);
	  return utils.integerToByteArr(env, result);
}


/*
 * 
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_trapdoor_1permutation_cryptopp_CryptoPpTrapdoorPermutation_deleteTP
  (JNIEnv *, jobject, jlong);

