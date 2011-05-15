#include "stdafx.h"
#include "Utils.h"
#include "Integer.h";
#include <iostream>;


/* function Utils	: constructor
 * return			: void
 */
void Utils::Utils() {}

/* function byteArrToInteger : This function converting from jbyteArray to Integer
 * param env	             : the jni pointer
 * param byteArrToInteger	 : the byte array to convert
 * return				     : the result
 */
Integer Utils::byteArrToInteger (JNIEnv *env, jbyteArray byteArrToConvert) {

	jchar* jcharToInteger;
	const char* charToInteger;

	// convert the jbyteArray to jchar
	jcharToInteger  = env -> GetCharArrayElements((jcharArray) byteArrToConvert, 0);
	//convert the jchar to const char*
	charToInteger = (const char*) jcharToInteger;
	
	//build and return the Integer
	return Integer(charToInteger);
}

jbyteArray Utils::integerToByteArr (JNIEnv *env, Integer integerToConvet) {
	
	byte* byteValue = new byte[integerToConvet.ByteCount()];

	//convert the Integer to byteArray
	integerToConvet.Encode(byteValue, integerToConvet.ByteCount(), Integer::UNSIGNED);

	//build and return the Integer
	return (jbyteArray) byteValue;

}


