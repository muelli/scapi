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
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * @author LabTest
 * 
 * 
 */
public abstract class PrfVaryingFromPrfVaryingInput implements PrfVaryingIOLength {
	
	protected PrfVaryingInputLength prfVaryingInputLength;
	protected AlgorithmParameterSpec params = null;
	protected SecretKey secretKey = null;
	protected boolean isInitialized = false;//until isInitialized() is called set to false. 
	
	
	/** 
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 */
	
	public void init(SecretKey secretKey) {

		isInitialized = true;
		this.secretKey = secretKey;
		
	}

	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return isInitialized;
	}

	/**
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key
	 * @param secretKey the secrete key
	 * @throws InvalidParameterSpecException 
	 */
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException {

		isInitialized = true;
		this.secretKey = secretKey;
		this.params = params;
		
	}
	
	/** 
	 * @return the parameters spec
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}



	/**
	 * @return - the secret key
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		return secretKey;
	}



	/** 
	 * Since both Input and output variables are varing this function should not be call. Throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		throw new IllegalBlockSizeException("Input and output sizes are not specified");
		
	}



	/** 
	 * Since both Input and output variables are varying this function should not be call. Throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		throw new IllegalBlockSizeException("Output size is not specified");
		
	}


	
}