/**
 * Pseudorandom function definition: In cryptography, a pseudorandom function family, abbreviated PRF, 
 * is a collection of efficiently-computable functions which emulate a random oracle in the following way: 
 * no efficient algorithm can distinguish (with significant advantage) between a function chosen randomly from the PRF family and a random oracle 
 * (a function whose outputs are fixed completely at random).Pseudorandom function is the root of this family
 */
package edu.biu.scapi.primitives.prf;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;


/** 
 * @author LabTest
 */
public interface PseudorandomFunction {
	/**
	 * Initializes this prf with the secret key
	 * @param secretKey - the secrete key
	 *  */
	public void init(SecretKey secretKey);

	/** 
	 * Initializes this prf with the secret key and the auxiliary parameters
	 * @param secretKey - secret key
	 * @param params - algorithm parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this prf
	 */
	public AlgorithmParameterSpec getParams();

	
	/** 
	 * @return the secret key
	 */
	public SecretKey getSecretKey();


	/** 
	 * @return The algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @return
	 */
	public int getBlockSize();

	/** 
	 * @param inBytes - input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException;
	
	/**
	 * 
	 * computetBlock
	 * 
	 * This function is necessary since some of the Prf's we implement may have variable input and output length.
	 * If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advence and 
	 * the use may call the other computeBlock function where length is not require
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException;
	
	/**
	 * 
	 * computetBlock
	 * 
	 * This function is necessary since some of the Prf's we implement may have only variable input and fixed output length.
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset) throws IllegalBlockSizeException;;

	
}