#include "StdAfx.h"
#include "Utils.h"

#include <stdlib.h>

big byteArrayToMiraclBig(JNIEnv *env, miracl *mip, jbyteArray byteArrToConvert){
	  
	//get jbyte* from byteArrToConvert
	jbyte* pjbyte  = (*env)->GetByteArrayElements(env, byteArrToConvert, 0);
	big result;

	result = mirvar(mip,0);  
	bytes_to_big(mip, (*env)->GetArrayLength(env, byteArrToConvert), (char*)pjbyte, result);
	
	//release jbyte
	(*env) ->ReleaseByteArrayElements(env, byteArrToConvert, pjbyte, 0);

	//return the Integer
	return result;
}

jbyteArray miraclBigToJbyteArray(JNIEnv *env, miracl *mip, big bigToConvert){

	int size = (int)(bigToConvert->len&MR_OBITS)*(MIRACL/8);
	char* bytesValue = (char*) calloc(size, sizeof(char));
	jbyteArray result;

	big_to_bytes(mip, size, bigToConvert, bytesValue, TRUE);

	//build jbyteArray from the byteArray
	result = (*env)-> NewByteArray(env, size);
	
	(*env)->SetByteArrayRegion(env, result, 0, size, (jbyte*)bytesValue);
	
	 //delete the allocated memory
	free(bytesValue);

	//return the jbyteArray
	return result;
}