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
public abstract class PrpFromPrfFixed implements PrpFixed {
	
	
	protected PrfFixed prfFixed;
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;
	
	/** 
	 * Initializes this PrpFromPrfFixed with the secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 */
	
	public void init(SecretKey secretKey) {

		this.secretKey = secretKey;
		
	}



	/**
	 * Initializes this PrpFromPrfFixed with the secret key
	 * @param secretKey the secrete key
	 * @param params the auxiliary parameters
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
	 * @return the secret key
	 */
	public SecretKey getSecretKey() {
		return secretKey;
	}



	/** 
	 * Since both Input and output variables are fixed this function should not normally be call. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes,
			int outOff, int outLen) throws IllegalBlockSizeException {

		if (inLen==outLen && inLen==getBlockSize())
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}



	/** 
	 * Since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified input length should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException {

		if (inLen==getBlockSize())//the length is correct
			//call the derived class implementation of computeBlock ignoring inLen
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}

	/**
	 * Since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len<code> should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception. 
	 * @param inBytes input bytes to invert
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param len the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException {
		
		if (len==getBlockSize())//the length is correct
			//call the derived class implementation of invertBlock ignoring len
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}
	
	
}