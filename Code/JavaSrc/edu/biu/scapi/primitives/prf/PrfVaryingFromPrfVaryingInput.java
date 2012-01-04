package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of varying input and output length prf classes.
 * 
 * PrfVaryingFromPrfVaryingInput is a pseudorandom function with varying input/output lengths, based on HMAC or any other implementation 
 * of PrfVaryingInputLength. We take the interpretation that there is essentially a different random function for every output length. 
 * This can be modeled by applying the random function to the input and the required output length (given as input to the oracle). 
 * The pseudorandom function must then be indistinguishable from this.
 * We use PrfVaryingInputLength for this construction because the input length can already be varying; this makes the construction more simple and efficient. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class PrfVaryingFromPrfVaryingInput implements PrfVaryingIOLength {
	
	protected PrfVaryingInputLength prfVaryingInputLength; //the underlying prf varying input
	
	
	/** 
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key.
	 * @param secretKey secret key
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey) throws InvalidKeyException {

		prfVaryingInputLength.init(secretKey); //initializes the underlying prf
		
	}

	/**
	 * Initializes this PrfVaryingFromPrfVaryingInput with the secret key and the auxiliary parameters
	 * @param secretKey the secrete key
	 * @param params algorithm parameters
	 * @throws InvalidParameterSpecException 
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException, InvalidKeyException {

		prfVaryingInputLength.init(secretKey, params); //initializes the underlying prf
		
	}
	
	public boolean isInitialized(){
		return prfVaryingInputLength.isInitialized();
	}
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
	
		return prfVaryingInputLength.getParams();
	}

	/** 
	 * Since both input and output variables are varying this function should not be call. Throws an exception.
	 * 
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
	 * Since both input and output variables are varying this function should not be call. Throws an exception.
	 * 
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