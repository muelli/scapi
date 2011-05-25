/**
 * A pseudorandom permutation with varying input/output lengths does not have predefined input /output lengths. 
 * The input and output length (that must be equal) may be different for each function call. 
 * The length of the input/output is determined upon user request. 
 * The interface PrpVaryingIOLength, groups and provides type safety for every PRP with varying input/output length. 
 */
package edu.biu.scapi.primitives.prf;

/** 
  * @author LabTest
 */
public interface PrpVaryingIOLength extends PseudorandomPermutation,
		PrfVaryingIOLength {
}