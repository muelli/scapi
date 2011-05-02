/**
 * A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, 
 * the (cryptographic) hash value. There are two main levels of security that we will consider here: 
 * target collision resistance (meaning that given x it is hard to find y such that H(y)=H(x)) and collision resistant for which we also 
 * have an interface. 
 */
package edu.biu.scapi.primitives.crypto.hash;

import java.security.spec.AlgorithmParameterSpec;

/** 
 * @author LabTest
 */
public interface TargetCollisionResistant {
	
	
	/** 
	 * Initializes this target collision resistant hash with the auxiliary parameters
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this target collision resistant hash
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return The algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @return the size of the hashed massage
	 */
	public int getHashedMsgSize();

	/**
	 * update : Adds the byte array to the existing msg to hash. 
	 * @param in - input byte array
	 * @param inOffset - the offset within the byte arrat
	 * @param inLen - the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen);

	/** 
	 * @param out - the output in byte arrat
	 * @param outOffset - the offset from which to take bytes from
	 */
	public void hashFinal(byte[] out, int outOffset);
}