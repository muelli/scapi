#include "StdAfx.h"
#include <jni.h>
#include "Dlog.h"
#include "Utils.h"
#include "miracl.h"
#include <stdlib.h>
#include <math.h>

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclAdapterDlogEC_createMip
  (JNIEnv *env, jobject obj){
	 // miracl* mip = mirsys(50, 0);
	  miracl* mip = mirsys(400, 16);
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

	  mirkill(a);
	  mirkill(b);
	  mirkill(p);
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

	  mirkill(a);
	  mirkill(b);
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
	  
	  mirkill(x);
	  mirkill(y);
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

	  mirkill(x);
	  mirkill(y);
	  /* The multiply operation is converted to addition because miracl treat EC as additive group */
	  ecurve2_add(mip, (epoint*)p1, p3);

	  return (jlong)p3; //return the result
	  
}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_simultaneousMultiplyF2m
  (JNIEnv *env, jobject obj, jlong m, jlongArray elements, jobjectArray exponents){

	  
	  int size = env->GetArrayLength(elements); //number of points
	  jlong* longElements  = env->GetLongArrayElements(elements, 0); //convert JllongArray to long array
	  epoint ** points = (epoint**) calloc(size, sizeof(epoint*)); //create a big array to hold the points
	  big* bigExponents =  (big*) calloc(size, sizeof(big)); //create a big array to hold the exponents
	  int i;
	  epoint *p;
	  jbyteArray exponent;

	  /* convert the accepted parameters to MIRACL parameters */
	  miracl* mip = (miracl*)m;

	  for(i=0; i<size; i++){
		  points[i] = (epoint*) longElements[i];
		  exponent = (jbyteArray) env->GetObjectArrayElement(exponents, i);
		  bigExponents[i] = byteArrayToMiraclBig(env, mip, exponent);
	  }

	  //p = epoint_init(mip);
	 
	 // ecurve2_multn(mip, size, bigExponents, points, p);

	  p = computeLL(mip, points, bigExponents, size, 0);
	  //release the memory
	  for(i=0; i<size; i++){
		  mirkill(bigExponents[i]);
	  }

	  free(points);
	  free(bigExponents);
	  //release jbyte
	  env ->ReleaseLongArrayElements(elements, longElements, 0);

	  return (jlong)p; //return the result
}

JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_simultaneousMultiplyFp
  (JNIEnv *env, jobject obj, jlong m, jlongArray elements, jobjectArray exponents){

	  int size = env->GetArrayLength(elements); //number of points
	  jlong* longElements  = env->GetLongArrayElements(elements, 0); //convert JllongArray to long array
	  epoint ** points = (epoint**) calloc(size, sizeof(epoint*)); //create a big array to hold the points
	  big* bigExponents =  (big*) calloc(size, sizeof(big)); //create a big array to hold the exponents
	  int i;
	  epoint *p;
	  jbyteArray exponent;
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  for(i=0; i<size; i++){
		  points[i] = (epoint*) longElements[i];
		  exponent = (jbyteArray) env->GetObjectArrayElement(exponents, i);
		  bigExponents[i] = byteArrayToMiraclBig(env, mip, exponent);
	  }

	 // p = epoint_init(mip);
	 
	  //ecurve_multn(mip, size, bigExponents, points, p);

	   p = computeLL(mip, points, bigExponents, size, 1);

	  //release the memory
	  for(i=0; i<size; i++){
		  mirkill(bigExponents[i]);
	  }

	  free(points);
	  free(bigExponents);

	  //release jbyte
	  env ->ReleaseLongArrayElements(elements, longElements, 0);

	  return (jlong)p; //return the result
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
	  
	  mirkill(exp);

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
	  
	  mirkill(exp);
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

	  mirkill(x);
	  mirkill(y);
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

	  mirkill(x);
	  mirkill(y);
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
	 
	  jboolean result;

	  genX= mirvar(mip, 0);
	  genY= mirvar(mip, 0);
	  epoint_get(mip, (epoint*)generator, genX, genY);
	  
	 
	  /* check if the values are as expected, return the result */
	  if (compare(genX, x)==0 && compare(genY, y)==0)
		  result = 1;
	  else result = 0;

	  mirkill(x);
	  mirkill(y);
	  mirkill(genX);
	  mirkill(genY);
	  return result;
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
	  jboolean result;

	  genX= mirvar(mip, 0);
	  genY= mirvar(mip, 0);
	  epoint2_get(mip, (epoint*)generator, genX, genY);

	  /* check if the values are as expected, return the result */
	  if (compare(genX, x)==0 && compare(genY, y)==0)
		 result = 1;
	  else result = 0;

	  mirkill(x);
	  mirkill(y);
	  mirkill(genX);
	  mirkill(genY);
	  return result;
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
	  
	  mirkill(x);
	  mirkill(y);
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
	  
	  mirkill(x);
	  mirkill(y);
	  
	  return member;
}

/* function createInfinityFpPoint	: This function creates the infinity point in Fp
 * param m							: miracl pointer
 * return							: true if the point is on the curve, false otherwise 
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECFp_createInfinityFpPoint
  (JNIEnv *env, jobject obj, jlong m){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  //create a point with the coordinates 0,0 which is the infinity point in miracl implementation
	  big x,y;
	  epoint* p = epoint_init(mip);
	  x = mirvar(mip, 0);
	  y = mirvar(mip, 0);
	  
	  epoint_set(mip, x, y, 0, (epoint*)p);

	  mirkill(x);
	  mirkill(y);

	  return (jlong) p;

}

/* function createInfinityF2mPoint	: This function creates the infinity point in F2m
 * param m							: miracl pointer
 * return							: true if the point is on the curve, false otherwise 
 */
JNIEXPORT jlong JNICALL Java_edu_biu_scapi_primitives_dlog_miracl_MiraclDlogECF2m_createInfinityF2mPoint
  (JNIEnv *env, jobject obj, jlong m){
	  /* convert the accepted parameters to MIRACL parameters*/
	  miracl* mip = (miracl*)m;

	  //create a point with the coordinates 0,0 which is the infinity point in miracl implementation
	  big x,y;
	  epoint* p = epoint_init(mip);
	  x = mirvar(mip, 0);
	  y = mirvar(mip, 0);
	 
	  epoint2_set(mip, x, y, 0, (epoint*)p);

	  mirkill(x);
	  mirkill(y);
	  return (jlong) p;

}



epoint* computeLL(miracl* mip, epoint** elements, big* exponents, int n, int field){
		
	big bigExp =  mirvar(mip, 0);
	big two = mirvar(mip, 2);
	big zero = mirvar(mip, 0);
	int t = 0, w, h, i, j;
	epoint*** preComp;
	epoint* result;

	//get the biggest exponent
	for (i=0; i<n; i++)
		if (compare(bigExp, exponents[i]) < 0)
			bigExp = exponents[i];
	//num of bitf in the biggest exponent
	t = logb2(mip, bigExp);

	//choose w according to the value of t
	w = getLLW(t);
		
	//h = n/w
	if ((n % w) == 0){
		h = n / w;
	} else{
		h = ((int) (n / w)) + 1;
	}
		
	printf("n is: %d\n", n);
	printf("t is: %d\n", t);
	printf("w is: %d\n", w);
	printf("h is: %d\n", h);

	//creates pre computation table
	preComp = createLLPreCompTable(mip, elements, w, h, n, field);
		
	result = getIdentity(mip, field); //holds the computation result		
		
	//computes the loop of the computation
	result = computeLoop(mip, exponents, w, h, preComp, result, t-1, n, field);
	
	//third part of computation
	for (j=t-2; j>=0; j--){
		//operate y^2 differently. depends on the field type
		if (field==1)
			ecurve_mult(mip, two, result, result);
		else
			ecurve2_mult(mip, two, result, result);
		//computes the loop of the computation
		result = computeLoop(mip, exponents, w, h, preComp, result, j, n, field);
	}
		
	//free the allocated memeory
	mirkill(two);
	mirkill(zero);

	for (i=0; i<h; i++){
		for (j=0; j<pow((double)2, w); j++){
			epoint_free(preComp[i][j]);
		}
		free(preComp[i]);
	}
	free(preComp);

	return result;
}

/*
 * return the w value that depends on the t bits
 *
 */
int getLLW(int t){
	int w;
	//choose w according to the value of t
	if (t <= 10){
		w = 2;
	} else if (t <= 24){
		w = 3;
	} else if (t <= 60){
		w = 4;
	} else if (t <= 144){
		w = 5;
	} else if (t <= 342){
		w = 6;
	} else if (t <= 797){
		w = 7;
	} else if (t <= 1828){
		w = 8;
	} else {
		w = 9;
	}
	return w;
}

/*
 * computes the loop of the algorithm.
 * for k=0 to h-1 
 *		e=0
 *		for i=kw to kw+w-1 
 *			if the bitIndex bit in ci is set:
 *			calculate e += 2^(i-kw)
 *		result = result *preComp[k][e]
 */
epoint* computeLoop(miracl* mip, big* exponentiations, int w, int h, epoint*** preComp, epoint* result, int bitIndex, int n, int field){
	int e = 0, k, i, twoPow;
	big temp = mirvar(mip, 0);

	for (k=0; k<h; k++){
		
		for (i=k*w; i<(k * w + w); i++){
			if (i < n){
				copy(exponentiations[i], temp);
				
				//check if the bit in bitIndex is set.
				//shift the big number bitIndex times
				sftbit(mip, temp, bitIndex*-1, temp);
			
				//check if the shifted big is divisible by two. if not - the first bit is set. 
				if (subdivisible(mip, temp, 2) == 0){
					twoPow = pow((double)2, i-k*w);
					e += twoPow;
				}
			}
		}
		//multiply operation depends on the field
		if (field == 1)
			ecurve_add(mip, preComp[k][e], result);
		else 
			ecurve2_add(mip, preComp[k][e], result);
		e = 0;
	}
		
	mirkill(temp);

	return result;
}

/*
 * Creates pre computation table
 */
epoint*** createLLPreCompTable(miracl* mip, epoint** points, int w, int h, int n, int field){
	//create the pre-computation table of size h*(2^(w))
	int twoPowW = pow((double)2, w);
	//allocates memory for the table
	epoint *** preComp = (epoint***) calloc(h, sizeof(epoint**)); //create a big array to hold the points
	epoint* base = epoint_init(mip);
	int baseIndex, k, e, i;
	big x,y;
	x = mirvar(mip, 0);
	y = mirvar(mip, 0);

	for (i=0; i<h; i++){
		preComp[i] = (epoint**) calloc(twoPowW, sizeof(epoint*));
	}
	
	//fill the table
	for (k=0; k<h; k++){
		for (e=0; e<twoPowW; e++){
			preComp[k][e] = getIdentity(mip, field);
			for (i=0; i<w; i++){
				baseIndex = k*w + i;
				if (baseIndex < n){
					if (field == 1){
						epoint_copy(points[baseIndex], base);
					} else {
						epoint2_copy(points[baseIndex], base);
					}
					if ((e & (1 << i)) != 0){ //bit i is set
						if (field == 1){
							ecurve_add(mip, base, preComp[k][e]);
						} else {
							ecurve2_add(mip, base, preComp[k][e]);
						}
					}
				}
			}
		}
	}
		
	epoint_free(base);

	/*for (i=0; i<h; i++){
		for (j=0; j<twoPowW; j++){
			epoint_get(mip, preComp[i][j], x, y);
			printf("before delete preComp[%d][%d]\n", i, j);
			epoint_free(preComp[i][j]);
			printf("delete preComp[%d][%d]\n", i, j);
		}
		free(preComp[i]);
	}
	free(preComp);
	printf("deleted table\n");*/
	return preComp;
		
}

/*
 * Returns the identity point
 */
epoint* getIdentity(miracl* mip, int field){
	big x,y;
	epoint* identity = epoint_init(mip);

	x = mirvar(mip, 0);
	y = mirvar(mip, 0);
	//creation of the point depends on the field type
	if (field == 1)
		epoint_set(mip, x, y, 0, identity);
	else
		epoint2_set(mip, x, y, 0, identity);

	mirkill(x);
	mirkill(y);
	return identity;
}