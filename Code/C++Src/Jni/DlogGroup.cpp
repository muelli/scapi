#include "stdafx.h"
#include "DlogGroup.h"
#include "Utils.h"
#include "cryptlib.h"
#include "gfpcrypt.h"
#include "osrng.h"

using namespace CryptoPP;

/* function createDlogZp : This function creates a Dlog group over Zp and returns a pointer to the created Dlog.
 * param p				 : field size (prime)
 * param element		 : generator of the group
 * return			     : A pointer to the created Dlog.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_createDlogZp
  (JNIEnv *env, jobject, jbyteArray p, jlong element){
	  Utils utils;

	  //convert to Integer
	  Integer integerP = utils.jbyteArrayToCryptoPPInteger(env, p);

	  //create the Dlog group and initialise it with the size and generator
	  DL_GroupParameters_GFP * group = new DL_GroupParameters_GFP();
	  group->Initialize(integerP,  *(Integer*) element);

	  return (jlong) group; //return pointer to the group
}

/* function inverseElement : This function return the inverse of the accepted element
 * param group			   : pointer to the group
 * param element		   : element to find inverse
 * return			       : A pointer to the inverse element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_inverseElement
  (JNIEnv *, jobject, jlong group, jlong element){
	  Utils utils;

	  Integer mod = ((DL_GroupParameters_GFP*) group)->GetModulus(); //get the field modulus
	  ModularArithmetic ma(mod); //create ModularArithmetic object with the modulus

	  // get the inverse 
	  Integer result = ma.MultiplicativeInverse( *(Integer*)element);

	  // get pointer to the result and return it
	  return (jlong)utils.getPointerToInteger(result);
}

/* function exponentiateElement : This function exponentiate the accepted element
 * param group			   : pointer to the group
 * param element		   : element to exponentiate
 * param exponent
 * return			       : A pointer to the result element.
 */
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

/* function multiplyElements : This function multiplies two elements
 * param group			   : pointer to the group
 * param element1		    
 * param element2
 * return			       : A pointer to the result element.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_multiplyElements
  (JNIEnv *, jobject, jlong group, jlong element1, jlong element2){
	  Utils utils;

	  //multiply the element
	  Integer result = ((DL_GroupParameters_GFP*) group)->MultiplyElements(*(Integer*) element1, *(Integer*) element2);

	  //get pointer to the result and return it
	  Integer* resultP = utils.getPointerToInteger(result);
	  return (jlong)resultP;
}

/*
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_validateZpGroup
  (JNIEnv *, jobject, jlong group){
	  //Random Number Generator
	  AutoSeededRandomPool rng;
	  Integer p, q,g;
	  bool res = false;

	  res = ((DL_GroupParameters_GFP*) group)->ValidateGroup(rng, 3);
	  
	  p = ((DL_GroupParameters_GFP*) group)->GetModulus();
	  q = ((DL_GroupParameters_GFP*) group)->GetSubgroupOrder();
	  g = ((DL_GroupParameters_GFP*) group)->GetGenerator();
	 
	  ModularArithmetic ma(p); //create ModularArithmetic object with the modulus
	  Integer v = ma.Exponentiate(g, q);
	  if(v != Integer::One())
		  res = false;

	  return res;


}

/*
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_validateZpGenerator
  (JNIEnv *, jobject, jlong group){
	  Integer p, q,g;
	  bool res = false;
	  p = ((DL_GroupParameters_GFP*) group)->GetModulus();
	  q = ((DL_GroupParameters_GFP*) group)->GetSubgroupOrder();
	  g = ((DL_GroupParameters_GFP*) group)->GetGenerator();
	 
	  res = ((DL_GroupParameters_GFP*) group)->ValidateElement(3, g, 0);

	  if (g.Compare(1))
		  res = false;
	  ModularArithmetic ma(p); //create ModularArithmetic object with the modulus
	  Integer v = ma.Exponentiate(g, q);
	  if(v != Integer::One())
		  res = false;

	  return res;
}

/* function deleteDlogZp   : This function frees the allocated memory
 * param groupPtr		   : pointer to the group
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_cryptopp_CryptoPpDlogZp_deleteDlogZp
  (JNIEnv *, jobject, jlong groupPtr){
	  //free the allocated memory
	  delete((void*) groupPtr);
}