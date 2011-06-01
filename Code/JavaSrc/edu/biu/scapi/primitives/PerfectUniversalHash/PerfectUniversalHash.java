/**
 * A universal hash function is a family of hash functions (as in the sense of hash functions for data structures) with the property that 
 * a randomly chosen hash function (from the family) yields very few collisions, with good probability. 
 * More importantly in a cryptographic context, universal hash functions have important properties, like good randomness extraction and 
 * pairwise independence. Many universal families are known (for hashing integers, vectors, strings), and their evaluation is often very efficient.
 * The notions of perfect universal hashing and collision resistance hash are distinct, and should not be confused (it is unfortunate that they 
 * have a similar name). We therefore completely separate the two implementations so that collision-resistant hash functions cannot be confused 
 * with perfect universal hash functions.
 * 
 * The input and output lengths of a perfect universal hash function are fixed for any given instantiation, and are set upon init.
 */
package edu.biu.scapi.primitives.PerfectUniversalHash;

import java.security.spec.AlgorithmParameterSpec;

/** 
 @author LabTest
 */
public interface PerfectUniversalHash {
	/**
	 * Initialize this perfect universal hash with the auxiliary parameters 
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params);

	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized();
	
	/** 
	 * @return the parameter spec of this perfect universal hash
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @return the input size of this hash function
	 */
	public int geInputSize();

	/** 
	 * @return the output size of this hash function
	 */
	public int geOutputSize();

	/** 
	 * Compute the hash function on the in byte array and put the result in the output byte array
	 * @param in - input byte array
	 * @param inOffset - the offset within the input byte array
	 * @param inLen - length. The number of bytes to take after the offset
	 * @param out - output byte array
	 * @param outOffset - the offset within the output byte array
	 */
	public void compute(byte[] in, int inOffset, byte[] out,
			int outOffset);
}