/**
 * A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, 
 * the (cryptographic) hash value. There are two main levels of security that we will consider here: 
 * target collision resistance (meaning that given x it is hard to find y such that H(y)=H(x)) and collision resistant for which we also 
 * have an interface. 
 */
package edu.biu.scapi.primitives.hash;

import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.exceptions.UnInitializedException;

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
	 * Initializes this target collision resistant hash. Does not require parameters
	 */
	public void init();
	
	/**
	 * 
	 * @return true if the object was initialized. Usually this means that the function init was called
	 */
	public boolean isInitialized();

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
	 * Adds the byte array to the existing message to hash. 
	 * @param in input byte array
	 * @param inOffset the offset within the byte array
	 * @param inLen the length. The number of bytes to take after the offset
	 * @throws UnInitializedException 
	 * */
	public void update(byte[] in, int inOffset, int inLen) throws UnInitializedException;

	/** 
	 * Completes the hash computation and puts the result in the out array.
	 * @param out the output in byte array
	 * @param outOffset the offset from which to take bytes from
	 * @throws UnInitializedException 
	 */
	public void hashFinal(byte[] out, int outOffset) throws UnInitializedException;
}