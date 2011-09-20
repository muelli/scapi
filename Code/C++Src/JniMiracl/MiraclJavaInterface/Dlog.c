#include "StdAfx.h"
#include <jni.h>
#include "Dlog.h"
#include "Utils.h"
#include "miracl.h"

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclAdapterDlogEC_createMip
  (JNIEnv *env, jobject obj){
	  miracl* mip = mirsys(50, 0);

	  return (jlong)mip; //return the pointer
}

/* function initFpCurve : This function initializes an elliptic curve over Fp according to the accepted values
 * param p				  : field's prime
 * param aVal			  : a value of the equation
 * param bVal			  : b value of the equation
 * return			      : the created miracl pointer.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_initFpCurve
  (JNIEnv *env, jobject obj, jlong m, jbyteArray pVal, jbyteArray aVal, jbyteArray bVal){
	  big p, a, b;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  p = byteArrayToMiraclBig(env, mip, pVal);
	  a = byteArrayToMiraclBig(env, mip, aVal);
	  b = byteArrayToMiraclBig(env, mip, bVal);
		  
	  /* initialize the curve */
	  ecurve_init(mip, a, b, p, MR_PROJECTIVE);
}

/* function initF2mCurve : This function initializes an elliptic curve over F2m according to the accepted values
 * param m				  : 
 * param k1				  : The integer k1 where x^m+x^k1+x^k2+x^k3+1 represents the reduction polynomial f(z)
 * param k2				  : The integer k2 where x^m+x^k1+x^k2+x^k3+1 represents the reduction polynomial f(z)
 * param k3				  : The integer k3 where x^m+x^k1+x^k2+x^k3+1 represents the reduction polynomial f(z)
 * param aVal			  : a value of the equation
 * param bVal			  : b value of the equation
 * return			      : the created miracl pointer.
 */
JNIEXPORT void JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_initF2mCurve
  (JNIEnv *env, jobject obj, jlong m, jint mod, jint k1, jint k2, jint k3, jbyteArray aVal, jbyteArray bVal){
	  big a, b;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  a = byteArrayToMiraclBig(env, mip, aVal);
	  b = byteArrayToMiraclBig(env, mip, bVal);

	  /* initialize the curve */
	  ecurve2_init(mip, mod, k1, k2, k3, a, b, 0, MR_PROJECTIVE);

}

/* function multiplyFpPoints : This function multiplies two point of ec over Fp
 * param m				  : miracl pointer
 * param p1				  : ellitic curve point
 * param p2				  : ellitic curve point
 * return			      : the multiplication result
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_multiplyFpPoints
  (JNIEnv * env, jobject obj, jlong m, jlong p1, jlong p2){
	  big x, y;
	  epoint *p3;

	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  /* create the result point with the values of p2. This way, p2 values won't damage in the multiplication operation */
	  p3 = epoint_init(mip);
	  epoint_get(mip, (epoint*)p2, x, y);
	  epoint_set(mip, x,y,0, p3);
	  
	  /* The multiply operation is converted to addition because miracl treat EC as additive group */
	  ecurve_add(mip, (epoint*)p1, p3);

	  return (jlong)p3; //return the result
}

/* function multiplyF2mPoints : This function multiplies two point of ec over F2m
 * param m				  : miracl pointer
 * param p1				  : ellitic curve point
 * param p2				  : ellitic curve point
 * return			      : the multiplication result
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_multiplyF2mPoints
  (JNIEnv *env, jobject obj, jlong m, jlong p1, jlong p2){
	 big x, y;
	  epoint *p3;

	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  /* create the result point with the values of p2. This way, p2 values won't damage in the multiplication operation */
	  p3 = epoint_init(mip);
	  epoint2_get(mip, (epoint*)p2, x, y);
	  epoint2_set(mip, x,y,0, p3);

	  /* The multiply operation is converted to addition because miracl treat EC as additive group */
	  ecurve2_add(mip, (epoint*)p1, p3);

	  return (jlong)p3; //return the result
	  
}

/* function exponentiateFpPoint : This function exponentiate point of ec over Fp
 * param m				  : miracl pointer
 * param point			  : ellitic curve point
 * param exponent		  
 * return			      : the exponentiation result
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_exponentiateFpPoint
  (JNIEnv *env, jobject obj, jlong m, jlong point, jbyteArray exponent){
	  epoint *p2;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big exp = byteArrayToMiraclBig(env, mip, exponent);

	  //init the result point
	  p2 = epoint_init(mip);

	   /* The exponentiate operation is converted to multiplication because miracl treat EC as additive group */
	  ecurve_mult(mip, exp, (epoint*)point, p2);
	
	  return (jlong)p2; //return the result
}

/* function exponentiateF2mPoint : This function exponentiate point of ec over F2m
 * param m				  : miracl pointer
 * param point			  : ellitic curve point
 * param exponent		  
 * return			      : the exponentiation result
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_exponentiateF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jlong point, jbyteArray exponent){
	  epoint *p2;

	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big exp = byteArrayToMiraclBig(env, mip, exponent);

	  //init the result point
	  p2 = epoint_init(mip);
	 
	   /* The exponentiate operation is converted to multiplication because miracl treat EC as additive group */
	  ecurve2_mult(mip, exp, (epoint*)point, p2);

	  return (jlong)p2; //return the result
}

/* function invertFpPoint : This function return the inverse of ec point
 * param m				  : miracl pointer
 * param p1				  : ellitic curve point
 * return			      : the inverse point 
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_invertFpPoint
  (JNIEnv *env, jobject obj, jlong m, jlong p1){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big x, y;
	  epoint* p2;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //init the result point and copy the values to it
	  p2 = epoint_init(mip);
	  epoint_get(mip, (epoint*)p1, x, y);
	  epoint_set(mip, x,y,0, p2);

	  //inverse the point
	  epoint_negate(mip, p2);

	  return (jlong)p2; // return the inverse
}

/* function invertF2mPoint : This function return the inverse of ec point
 * param m				  : miracl pointer
 * param p1				  : ellitic curve point
 * return			      : the inverse point 
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_invertF2mPoint
  (JNIEnv *env, jobject obj, jlong m, jlong p1){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big x, y;
	  epoint* p2;
	  x= mirvar(mip, 0);
	  y= mirvar(mip, 0);

	  //init the result point and copy p1 values to it
	  p2 = epoint_init(mip);
	  epoint2_get(mip, (epoint*)p1, x, y);
	  epoint2_set(mip, x,y,0, p2);

	  //inverse the point
	  epoint2_negate(mip, p2);

	  return (jlong)p2; // return the inverse 
}

/* function validateFpGenerator : This function checks if the accepted point is the generator of EC over 
   Fp, by compare its values to the accepted x,y values
 * param m				  : miracl pointer
 * param generator		  : ellitic curve point to check
 * param xVal			  : x value of the generator
 * param yVal			  : y value of the generator
 * return			      : true if the generator is valid or not 
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_validateFpGenerator
  (JNIEnv *env, jobject obj, jlong m, jlong generator, jbyteArray xVal, jbyteArray yVal){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big x = byteArrayToMiraclBig(env, mip, xVal);
	  big y = byteArrayToMiraclBig(env, mip, yVal);
	  
	  /* get the point's x,y values */
	  big genX, genY;
	  genX= mirvar(mip, 0);
	  genY= mirvar(mip, 0);
	  epoint_get(mip, (epoint*)generator, genX, genY);
	  
	  /* check if the values are as expected, return the result */
	  if (compare(genX, x)==0 && compare(genY, y)==0)
		  return 1;
	  else return 0;
}

/* function validateF2mGenerator : This function checks if the accepted point is the generator of EC over 
   F2m, by compare its values to the accepted x,y values
 * param m				  : miracl pointer
 * param generator		  : ellitic curve point to check
 * param xVal			  : x value of the generator
 * param yVal			  : y value of the generator
 * return			      : true if the generator is valid or not 
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclAdapterDlogEC_validateF2mGenerator
  (JNIEnv *env, jobject obj, jlong m, jlong generator, jbyteArray xVal, jbyteArray yVal){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;
	  big x = byteArrayToMiraclBig(env, mip, xVal);
	  big y = byteArrayToMiraclBig(env, mip, yVal);

	  /* get the point's x,y values */
	  big genX, genY;
	  genX= mirvar(mip, 0);
	  genY= mirvar(mip, 0);
	  epoint2_get(mip, (epoint*)generator, genX, genY);

	  /* check if the values are as expected, return the result */
	  if (compare(genX, x)==0 && compare(genY, y)==0)
		  return 1;
	  else return 0;
}

/* function isFpMember : This function checks if the accepted point is a point of the current elliptic curve  (over Fp)
 * param m				  : miracl pointer
 * param point			  : ellitic curve point to check
 * return			      : true if the point is on the curve, false otherwise 
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_isFpMember
  (JNIEnv *env, jobject obj, jlong m, jlong point){
	  int member = 0;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  /* get the x,y, values of the point */
	  big x,y;
	  epoint* p = epoint_init(mip);
	  x = mirvar(mip, 0);
	  y = mirvar(mip, 0);
	  epoint_get(mip, (epoint*)point, x, y);

	  /* try to create another point with those values. if succeded - the point is in the curve */
	  if (epoint_set(mip, x, y, 0, p)==1)
		  member = 1;

	  return member; 
}


/* function isF2mMember : This function checks if the accepted point is a point of the current elliptic curve  (over F2m)
 * param m				  : miracl pointer
 * param point			  : ellitic curve point to check
 * return			      : true if the point is on the curve, false otherwise 
 */
JNIEXPORT jboolean JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_isF2mMember
  (JNIEnv *env, jobject obj, jlong m, jlong point){
	  int member = 0;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  /* get the x,y, values of the point */
	  big x,y;
	  epoint* p = epoint_init(mip);
	  x = mirvar(mip, 0);
	  y = mirvar(mip, 0);
	  epoint2_get(mip, (epoint*)point, x, y);

	   /* try to create another point with those values. if succeded - the point is in the curve */
	  if (epoint2_set(mip, x, y, 0, p)==1)
		  member = 1;

	  return member;
}





