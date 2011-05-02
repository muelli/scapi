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
package edu.biu.scapi.primitives.crypto.PerfectUniversalHash;

import java.security.spec.AlgorithmParameterSpec;

/** 
 @author LabTest
 */
public interface PerfectUniversalHash {
	/** 
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params);

	/** 
	 * @return
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return
	 */
	public String getAlgorithmName();

	/** 
	 * @return
	 */
	public int geInputSize();

	/** 
	 * @return
	 */
	public int geOutputSize();

	/** 
	 * @param in
	 * @param inOffset
	 * @param inLen
	 * @param out
	 * @param outOffset
	 */
	public void compute(byte[] in, int inOffset, byte[] out,
			int outOffset);
}