package edu.biu.scapi.primitives.prf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of PrpFixed by having an instance of prfFixed.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class PrpFromPrfFixed implements PrpFixed {
	
	protected PrfFixed prfFixed; //the underlying prf
	
	/**
	 * Initialized this PrpFromPrfFixed with a secretKey
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey) throws InvalidKeyException {
		//initializes the underlying prf with the secret key
		prfFixed.init(secretKey);
		
	}

	/**
	 * Initializes this PrpFromPrfFixed with the secret key and the auxiliary parameters.
	 * @param secretKey the secret key
	 * @param params the auxiliary parameters
	 * @throws InvalidParameterSpecException 
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException, InvalidKeyException {
		//initializes the underlying prf with the secret key and params
		prfFixed.init(secretKey, params);
		
	}
	
	public boolean isInitialized(){
		// call the underlying prf isInitialized function and return the result
		return prfFixed.isInitialized();
	}
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		// return the params of the underlying prf
		return prfFixed.getParams();
	}

	/** 
	 * Computes the function using the secret key. <p>
	 * 
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input and output length.
	 * Since this is a prp fixed, both input and output variables are equal and fixed, so this function should not normally be called. 
	 * If the user still wants to use this function, the specified arguments <code>inLen<code> and <code>outLen<code> should be the same as 
	 * the result of getBlockSize. otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param innLen input array length
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param outLen output array length
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes,
			int outOff, int outLen) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+outLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the input and output length are equal to the blockSize, call the computeBlock that doesn't take length arguments.
		if (inLen==outLen && inLen==getBlockSize())
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("input and output lengths should be equal to Block size");
		
	}

	
	/** 
	 * Computes the function using the secret key. <p>
	 * 
	 * This function is provided in this PseudorandomFunction interface for the sake of interfaces (or classes) for which 
	 * the input length can be different for each computation.
	 * Since in this case both input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified input length should be the same as 
	 * the result of getBlockSize, otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param inLen input array length
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff)
			throws IllegalBlockSizeException, UnInitializedException {
		
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		if (inLen==getBlockSize())//the length is correct
			//calls the derived class implementation of computeBlock ignoring inLen
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("input length should be the same as block size");
		
	}

	/**
	 * Inverts the permutation using the given key. <p>
	 * 
	 * This function is suitable for cases where the input/output lengths are varying.
	 * Since in this case, both input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len<code> should be the same as 
	 * the result of getBlockSize, otherwise, throws an exception. 
	 * 
	 * @param inBytes input bytes to invert
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert.
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param len the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+len > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+len > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		if (len==getBlockSize())//the length is correct
			//callt the derived class implementation of invertBlock ignoring len
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("the length should be the same as block size");
		
	}
	
	
}