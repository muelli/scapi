/**
 * 
 */
package edu.biu.scapi.primitives.prf;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * @author LabTest
 */
public abstract class PrpFromPrfVarying implements PrpVaryingIOLength {
	
	protected PrfVaryingIOLength prfVaryingIOLength;
	protected AlgorithmParameterSpec params = null;
	protected SecretKey secretKey = null;
	protected boolean isInitialized = false;//until isInitialized() is called set to false.
	
	/** 
	 * Initializes this PrpFromPrfVarying with the secret key and the auxiliary parameters
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 */
	
	public void init(SecretKey secretKey) {

		isInitialized = true;
		this.secretKey = secretKey;
		
	}



	/**
	 * Initializes this PrpFromPrfVarying with the secret key
	 * @param secretKey the secrete key
	 */
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		isInitialized = true;
		this.secretKey = secretKey;
		this.params = params;
		
	}
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return isInitialized;
	}
	
	/** 
	 * @return the parameters spec
	 */
	public AlgorithmParameterSpec getParams() {
		return params;
	}



	/**
	 * @return the secret key
	 */
	public SecretKey getSecretKey() {
		return secretKey;
	}



	/** 
	 * Since both Input and output variables are varying this function should not be called. Throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */

	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {

		throw new IllegalBlockSizeException("Input and output sizes are not specified");
		
	}



	/** 
	 * Since both Input and output variables are varying this function should not be called. Throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException {

		throw new IllegalBlockSizeException("Input size is not specified");
		
	}

	/**
	 * since both Input and output variables are varying this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len<code> should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception. 
	 * @param inBytes input bytes to invert
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param len the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {
		
		throw new IllegalBlockSizeException("Wrong size");
		
	}
	
	
}