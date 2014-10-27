#include "OTExtensionMaliciousReceiver.h"

/*
 * Function initOtReceiver : This function initializes the receiver object and 
 * creates the connection with the sender
 * 
 * param ipAddress : The ip address of the receiver computer for connection
 * param port : The port to be used for sending/receiving data over the network
 * returns : A pointer to the receiver object that was created and later be used to run the protcol
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_initOtReceiver(
JNIEnv *env, jobject, jstring ipAddress, jint port, jint koblitzOrZpSize, jint numOfthreads) {

  // globals that must be set:
  // m_bUseECC = true;
  // m_sSecLvl = LT;
  // m_nPID = 0; // role, 0 for sender, 1 for receiver
  // BYTE version = C_OT;//Choose OT extension version: G_OT, C_OT or R_OT
  // m_nNumOTThreads = 1;
  // m_nChecks = 380; //Number of checks between the base-OTs


  // deprecated

  // //use ECC koblitz
  // if(koblitzOrZpSize==163 || koblitzOrZpSize==233 || koblitzOrZpSize==283){

  //   m_bUseECC = true;
  //   //The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
  //   m_nSecParam = koblitzOrZpSize;
  // }
  // //use Zp
  // else if(koblitzOrZpSize==1024 || koblitzOrZpSize==2048 || koblitzOrZpSize==3072) {

  //   m_bUseECC = false;
  //   //The security parameter (163,233,283 for ECC or 1024, 2048, 3072 for FFC)
  //   m_nSecParam = koblitzOrZpSize;
  // }

  // get the ip address from java
  const char* address = env->GetStringUTFChars(ipAddress, NULL);
  
  return (jlong) InitOTReceiver(address, (int) port, (int) nbaseots, (int) numOTs);
}

/*
 * Function runOtAsReceiver : This function runs the ot extension as the sender.
 * 
 * param sigma : The input array that holds all the receiver inputs for each ot 
 * in a one dimensional array.
 * param bitLength : The length of each element
 * param output : An empty array that will be filled with the result of the ot 
 * extension in one dimensional array. That is, 
 * The relevant i'th element x1/x2 will be placed in the position bitLength*sizeof(BYTE).
*/
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_runOtAsReceiver(
JNIEnv *env, jobject, jlong receiver, jbyteArray sigma, jint numOfOts, 
jint bitLength, jbyteArray output, jstring version) {

}

/*
 * Function deleteReceiver : deletes the receiver object
 * param receiver: a pointer to the receiver object.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_interactiveMidProtocols_ot_otBatch_otExtension_OTExtensionMaliciousReceiver_deleteReceiver(JNIEnv *env, jobject, jlong receiver) {

  Cleanup();
  delete (Mal_OTExtensionReceiver*) receiver;
}
