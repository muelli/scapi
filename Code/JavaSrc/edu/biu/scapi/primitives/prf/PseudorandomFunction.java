/**
 * Pseudorandom function definition: In cryptography, a pseudorandom function family, abbreviated PRF, 
 * is a collection of efficiently-computable functions which emulate a random oracle in the following way: 
 * no efficient algorithm can distinguish (with significant advantage) between a function chosen randomly from the PRF family and a random oracle 
 * (a function whose outputs are fixed completely at random).Pseudorandom function is the root of this family
 */
package edu.biu.scapi.primitives.prf;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;


/** 
 * @author LabTest
 */
public interface PseudorandomFunction {
	/**
	 * Initializes this prf with the secret key.
	 * @param secretKey the secrete key
	 *  */
	public void init(SecretKey secretKey);

	/** 
	 * Initializes this prf with the secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 * @throws InvalidParameterSpecException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException;
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized();

	/** 
	 * @return the parameter spec of this prf
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException;

	
	/** 
	 * @return the secret key
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException;


	/** 
	 * @return The algorithm name
	 */
	public String getAlgorithmName() ;

	/** 
	 * @return 
	 */
	public int getBlockSize() ;

	/** 
	 * computeBlock : computes the function using the secret key. The user supplies the input byte array and the offset from 
	 * which to take the data from. The user also supplies the output byte array as well as the offset. 
	 * The computeBlock function will put the output starting at the offset. This function is suitable for block ciphers where 
	 * the input/output length is known in advance.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException, UnInitializedException;
	
	/**
	 * 
	 * computetBlock : This function is provided in the interface especially for the sub-family PrfVaryingInputLength
	 * 
	 * This function is necessary since some of the Prf's we implement may have variable input and output length.
	 * If the implemented algorithm is a block cipher then the size of the input as well as the output is known in advence and 
	 * the use may call the other computeBlock function where length is not require.
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException, UnInitializedException;
	
	/**
	 * 
	 * computetBlock : This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which 
	 * the input-output lengths can be different for each computation. Hmac and Prf/Prp with variable input/output length are examples of 
	 * such interfaces.
	 * 
	 * This function is necessary since some of the Prf's we implement may have only variable input and fixed output length.
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen, byte[] outBytes, int outOffset) throws IllegalBlockSizeException, UnInitializedException;;

	
}