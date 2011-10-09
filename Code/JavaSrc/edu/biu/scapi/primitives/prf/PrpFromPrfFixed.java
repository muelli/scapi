/**
 * 
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
public abstract class PrpFromPrfFixed implements PrpFixed {
	
	
	protected PrfFixed prfFixed;
	protected AlgorithmParameterSpec params = null;
	protected SecretKey secretKey = null;
	protected boolean isInitialized = false;//until isInitialized() is called set to false.
	
	public void init(SecretKey secretKey) {

		prfFixed.init(secretKey);
		
	}

	/**
	 * Initializes this PrpFromPrfFixed with the secret key
	 * @param secretKey the secrete key
	 * @param params the auxiliary parameters
	 * @throws InvalidParameterSpecException 
	 */
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException {

		prfFixed.init(secretKey, params);
		
	}
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return prfFixed.isInitialized();
	}
	
	
	/** 
	 * @return the parameters spec
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		return prfFixed.getParams();
	}



	/**
	 * @return the secret key
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException{
		return prfFixed.getSecretKey();
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
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes,
			int outOff, int outLen) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		/* check that the offset and length are correct */
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("input buffer too short");
		}
		if ((outOff > outBytes.length) || (outOff+outLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("output buffer too short");
		}
		
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
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException, UnInitializedException {
		
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		/* check that the offset and length are correct */
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("input buffer too short");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("output buffer too short");
		}
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
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		if (len==getBlockSize())//the length is correct
			//call the derived class implementation of invertBlock ignoring len
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}
	
	
}