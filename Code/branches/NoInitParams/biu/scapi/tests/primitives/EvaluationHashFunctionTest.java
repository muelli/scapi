package edu.biu.scapi.tests.primitives;

import edu.biu.scapi.primitives.universalHash.UniversalHash;

/**
 * This class tests the performance and correctness of any implemented EvaluationHashFunctionTest algorithm.
 * The are no known test vectors so we calculated some example an tested them.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class EvaluationHashFunctionTest extends UniversalHashTest {

	public EvaluationHashFunctionTest(UniversalHash puh) {
		super(puh);
		
		/*
		 * conversion from byte vector to polynomial:
		 * x = sum(p[i]*X^(8*i), i = 0..n-1), where the bits of p[i] are interpretted
		 * as a polynomial in the natural way (i.e., p[i] = 1 is interpretted as 1,
		 * p[i] = 2 is interpretted as X, p[i] = 3 is interpretted as X+1, etc.).
		 */
		//input - the related polynomial is P(y) = (1+x^16) + (1+x^16)y. 
		//with the padding the polynomial is P(y) = (1+x^16) + (1+x^16)y + y^2
		byte[] input = {1, 0, 1, 0, 0, 0, 0, 0, 	  1, 0, 1 ,0 ,0, 0, 0, 0};
		byte[] output = {0, 1, 1, 1, 1, 0, 0, 0};//output - the related polynomial is f(x) = x^8 + x^16 + x^32  
		byte[] key = {0, 1, 0, 0, 0, 0, 0, 0};//key - the related polynomial is f(x) = x^8
		
		
		addData(input ,output ,key);
		
		//byte[] inputToPad = {1, 0, 1, 0, 0, 0, 0, 0, 	  1, 0};
		//byte[] outputAfterPad = {0, 1, 1, 1, 1, 0, 0, 0};//output - the related polynomial is f(x) = x^8 + x^16 + x^32  

		//addData(inputToPad ,outputAfterPad ,key);
		
		//input - the related polynomial is P(y) = 1 + y
		//with the padding the polynomial is P(y) = P(y) = 1 + y + y^2
		byte[] input1 = {1, 0, 0, 0, 0, 0, 0, 0, 	  1, 0, 0 ,0 ,0, 0, 0, 0};
		byte[] output1 = {0, 0, 0, 0, 0, 0, 0, 0};//output - the related polynomial is f(x) = 1
		byte[] key1 = {1, 0, 0, 0, 0, 0, 0, 0};//key - the related polynomial is f(x) = 1
		
		addData( input1 ,output1 ,key1);
		
		byte[] input2 = {1, 3, 1, 0, 0, 0, 0, 0, 	0, 0, 0, 0, 0, 0, 0, 0,      1, 0, 1 ,0 ,0, 0, 0, 0};//input - the related polynomial is 
																										 //P(y) = (1 + x^8 + x^9 + x^16) + (1+x^16)y^2 + y^3
		byte[] output2 = {12, 1, 12, 5, 3, 1, 0, 0};//output - the related polynomial is f(x) = 1 + x^2 + x^3 + x^4 + x^8 + x^18 + x^19 + x^24 + x^26 + x^33 + x^40 
		byte[] key2 = {3, 1, 0, 0, 0, 0, 0, 0};//key - the related polynomial is f(x) = 1 + x + x^8
		
		addData( input2 ,output2 ,key2);
		
		
	}

}
