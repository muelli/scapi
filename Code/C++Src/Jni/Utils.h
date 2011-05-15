#ifndef UTILS_H
#define UTILS_H

#include "stdafx.h"
#include "jni.h" 
#include <string>
#include "cryptlib.h"

using namespace std;
using namespace CryptoPP;

class Utils {

public:

	Utils();
	Integer byteArrToInteger (JNIEnv *env, jbyteArray byteArrToConvert);
	jbyteArray integerToByteArr (JNIEnv *env, Integer integerToConvert);
};


#endif
