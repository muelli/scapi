/**
 * The class PrfVaryingFromPrfVaryingInput is also an implementation that has a varying input and output length. 
 * PrfVaryingFromPrfVaryingInput is a pseudorandom function with varying input/output lengths, based on HMAC or any other implementation 
 * of PrfVaryingInputLength. We take the interpretation that there is essentially a different random function for every output length. 
 * This can be modeled by applying the random function to the input and the required output length (given as input to the oracle). 
 * The pseudorandom function must then be indistinguishable from this.
 * We use PrfVaryingInputLength for this construction because the input length can already be varying; this makes the construction more simple and efficient. 
 */
package edu.biu.scapi.primitives.prf;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/** 
 * @author LabTest
 * 
 * 
 */
public abstract class PrfVaryingFromPrfVaryingInput implements PrfVaryingIOLength {
	
	protected PrfVaryingInputLength prfVaryingInputLength;
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;
	
	
	/** 
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key and the auxiliary parameters
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 */
	
	public void init(SecretKey secretKey) {

		this.secretKey = secretKey;
		
	}


	/**
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key
	 * @param secretKey the secrete key
	 */
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		this.secretKey = secretKey;
		this.params = params;
		
	}
	
	/** 
	 * @return the parameters spec
	 */
	public AlgorithmParameterSpec getParams() {
		return params;
	}



	/**
	 * @return - the secret key
	 */
	public SecretKey getSecretKey() {
		return secretKey;
	}



	/** 
	 * Since both Input and output variables are varing this function should not be call. Throw an exception.
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
	 * Since both Input and output variables are varying this function should not be call. Throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException {

		throw new IllegalBlockSizeException("Input size is not specified");
		
	}


	
}