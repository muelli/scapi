#include "StdAfx.h"
#include "ECF2mPoint.h"
#include <jni.h>
#include "Utils.h"
#include "miracl.h"

/* function createF2mPoint : This function creates a point of elliptic curve over F2m according to the accepted values
 * param m				  : pointer to mip
 * param xVal			  : x value of the point
 * param yVal			  : y value of the point
 * param validity	      : indicates if the point is valid for the current curve or not
 * return			      : A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbyteArray yVal,  jbooleanArray validity){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  jboolean* valid = (*env)->GetBooleanArrayElements(env, validity, 0);
	  
	   /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);
	  big y = byteArrayToMiraclBig(env, mip, yVal);

	  valid[0] = epoint2_set(mip, x, y, 0, p);

	  /* release the array */
	  (*env)->ReleaseBooleanArrayElements(env, validity, valid, 0);
	  
	  return (jlong) p; // return the point
}

/* function createF2mPointFromX : This function creates a point of elliptic curve over F2m according to the accepted values
 * param m						: pointer to mip
 * param xVal					: x value of the point
 * param validity				: indicates if the point is valid for the current curve or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createF2mPointFromX
  (JNIEnv *env, jobject obj, jlong m, jbyteArray xVal, jbooleanArray validity){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  jboolean* valid = (*env)->GetBooleanArrayElements(env, validity, 0);
	  
	   /* create the point with x,y values */
	  epoint* p = epoint_init(mip);
	  big x = byteArrayToMiraclBig(env, mip, xVal);

	  valid[0] = epoint2_set(mip, x, x, 1, p);

	  /* release the array */
	  (*env)->ReleaseBooleanArrayElements(env, validity, valid, 0);
	  
	  return (jlong) p; // return the point
}

/* function createRandomF2mPoint : This function creates a random point of elliptic curve over F2m
 * param m						: pointer to mip
 * param pVal					: field's prime 
 * param validity				: indicate if the point was created correctly or not
 * return						: A pointer to the created point.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_createRandomF2mPoint
	(JNIEnv *env, jobject obj, jlong m, jint mod, jbooleanArray validity){
	   /* convert the accepted parameters to MIRACL parameters*/
	   miracl* mip = (miracl*)m;
	   jboolean* valid = (*env)->GetBooleanArrayElements(env, validity, 0);
	   int i;

	   //create the point
	   epoint* point = epoint_init(mip);

	   /* choose randomly x,y values*/
	   int len = 2*mod;
	   big bigMod = mirvar(mip, 2^mod);
	   big x = mirvar(mip, 0);
	   for(i=0; i<len; i++){
		   irand(mip, i);
		   bigrand(mip, bigMod, x); //get a random number in the field
		   if (epoint2_set(mip, x, x,1 ,point)==1){
			   //set the point with tthe chosen x, miracl choose y value according to this x
			   valid[0] = 1;
			   i=len; //stop the loop
		   }
	   }
	   
	   /* release the jni array */
	   (*env)->ReleaseBooleanArrayElements(env, validity, valid, 0);
	  
	   return (jlong)point; // return the point
}

/* function checkInfinityF2m : This function checks if this point is the infinity
 * param point					: point to check
 * return						: true if this point is fthe infinity, false otherwise
 */

JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_checkInfinityF2m
  (JNIEnv *env, jobject obj, jlong point){

	  return point_at_infinity((epoint*)point);

}

/* function getXValue : This function return the x coordinate of the given point
 * param m			  : pointer to mip
 * param point		  : pointer to the point
 * return			  : the x coordinate of the given point
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_getXValueF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  big x, y;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint2_get(mip, (epoint*)point, x, y);

	  //return the bytes of x
	  return miraclBigToJbyteArray(env, mip, x);
}

/* function getYValue : This function return the y coordinate of the given point
 * param m			  : pointer to mip
 * param point		  : pointer to the point
 * return			  : the y coordinate of the given point
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECF2mPointMiracl_getYValueF2mPoint
  (JNIEnv * env, jobject obj, jlong m, jlong point){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  big x, y;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //get x, y values of the point
	  epoint2_get(mip, (epoint*)point, x, y);

	  //retur nthe bytes of x
	  return miraclBigToJbyteArray(env, mip, y);
}

/* function deletePointFp : This function deletes point of elliptic curve over Fp
 * param p				  : pointer to elliptic curve point
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_ECPointMiracl_deletePointF2m
  (JNIEnv *env, jobject obj, jlong m, jlong p){
	  epoint_free((epoint*)p);
}