#include "StdAfx.h"
#include "Utils.h"



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
