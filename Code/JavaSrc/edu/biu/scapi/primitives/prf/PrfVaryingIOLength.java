/**
 * A pseudorandom function with varying input/output lengths does not have pre-defined input and output lengths. 
 * The input and output length may be different for each compute function call. 
 * The length of the input as well as the output is determined upon user request.
 * The interface PrfVaryingIOLength, groups and provides type safety for every PRF with varying input and output length
 */
package edu.biu.scapi.primitives.prf;

/** 
 * @author LabTest
 */
public interface PrfVaryingIOLength extends PseudorandomFunction {
}