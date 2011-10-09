/**
 * A general adapter class of PrpFixed for Bouncy Castle. 
 * This class implements all the functionality by passing requests to the adaptee interface BlockCipher. 
 * A concrete PRP such as AES represented by the class BcAES only passes the AESEngine object in the constructor 
 * to the base class. 
 *  
 */
package edu.biu.scapi.primitives.prf.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.prf.PrpFixed;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
 * @author LabTest
 * 
 * 
 */
public abstract class BcPRP implements PrpFixed{
	
	private BlockCipher bcBlockCipher = null;//bc block cipher
	private CipherParameters bcParams = null;//bc parameters
	private boolean forEncryption = true;//set for true. If decryption is needed the flag will be set to false. 
	protected SecretKey secretKey = null;
	protected AlgorithmParameterSpec params = null;
	protected boolean isInitialized = false;//until isInitialized() is called set to false.
	

	/** 
	 * @param bcBlockCipher the underlying bc block cipher
	 */
	public BcPRP(BlockCipher bcBlockCipher) {
		
		this.bcBlockCipher = bcBlockCipher;
	}


	/** 
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey secret key
	 */
	public void init(SecretKey secretKey) {
		
		
		//init parameters
		isInitialized = true;
		this.secretKey = secretKey;
		
		//get the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//at the beginning forEncryption is set to true. Init the BC block cipher.
		bcBlockCipher.init(forEncryption, bcParams);
			
	}
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return isInitialized;
	}

	/** 
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 * @throws InvalidParameterSpecException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException {

		//init parameters
		isInitialized = true;
		this.secretKey = secretKey;
		this.params = params;
		
		//send the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey, params);
		
		//at the beginning forEncryption is set to true. Init the BC block cipher.
		bcBlockCipher.init(forEncryption, bcParams);
		
	}
	
	/**
	 *  
	 */
	public String getAlgorithmName() {
		return bcBlockCipher.getAlgorithmName();
	}

	/**  
	 * 
	 */
	public int getBlockSize(){
		
		return bcBlockCipher.getBlockSize();
	}

	/** 
	 * Call the underlying bc block cipher processBlock. Since we wish to computeBlock we first set the flag
	 * of forEncryption to true.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// check that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the bc block cipher is not already in encryption mode init the block cipher with forEncryption=true
		if(forEncryption==false){
			forEncryption = true;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//do the computeBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}
	
	/**
	 * 
	 * Call computeBlock if the input length is correct. Otherwise, throw an exception.
	 * 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOffset output offset in the outBytes array to take the result from
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// check that the offset and length are correct 
		if ((inOffset > inBytes.length) || (inOffset+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((inOffset > outBytes.length) || (inOffset+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		if(inLen==getBlockSize())
			computeBlock(inBytes, inOffset, outBytes, outOffset);
		else
			throw new IllegalBlockSizeException("Wrong size");
	}
	

	/** 
	 * Call the underlying bc block cipher processBlock. Since we wish to invertBlock we first set the flag
	 * of forEncryption to false.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) throws UnInitializedException {
		
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		
		//if the bc block cipher is not already in decryption mode init the block cipher with forEncryption=false
		if(forEncryption==true){
			forEncryption = false;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//do the invertBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}

	
	
	/**
	 *  since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len<code> should be the same as 
	 * the result of <code>getBlockSize<code>, otherwise, throw an exception. 
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
		// check that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+len > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((inOff > outBytes.length) || (inOff+len > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		if (len==getBlockSize())
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}

	/** 
	 * Since both Input and output variables are fixed this function should not normally be call. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of <code>getBlockSize<code>, otherwise, throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// check that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((inOff > outBytes.length) || (inOff+outLen > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		if (inLen==outLen && inLen==getBlockSize())
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
			
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
	 * @return the secret key
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		return secretKey;
	}
}