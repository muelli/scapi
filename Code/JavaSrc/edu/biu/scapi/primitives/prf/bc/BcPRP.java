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
 * A general adapter class of PrpFixed for Bouncy Castle. 
 * This class implements all the functionality by passing requests to the adaptee interface BlockCipher. 
 * A concrete PRP such as AES represented by the class BcAES only passes the AESEngine object in the constructor 
 * to the base class. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class BcPRP implements PrpFixed{
	
	private BlockCipher bcBlockCipher = null;//bc block cipher
	private CipherParameters bcParams = null;//bc parameters
	private boolean forEncryption = true;//set for true. If decryption is needed the flag will be set to false. 
	protected SecretKey secretKey = null;
	protected AlgorithmParameterSpec params = null;
	protected boolean isInitialized = false;//until init is called set to false.
	

	/** 
	 * Constructor that accepts a blockCipher to be the underlying blockCipher.
	 * 
	 * @param bcBlockCipher the underlying bc block cipher
	 */
	public BcPRP(BlockCipher bcBlockCipher) {
		
		this.bcBlockCipher = bcBlockCipher;
	}


	/** 
	 * Initializes this prp with the given secret key.
	 * @param secretKey secret key
	 */
	public void init(SecretKey secretKey) {
		
		/*
		 * Creates the relevant bc parameters to pass when inverting or computing.
		 */
		
		//init parameters
		this.secretKey = secretKey;
		
		//get the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//at the beginning forEncryption is set to true. Init the BC block cipher.
		bcBlockCipher.init(forEncryption, bcParams);
		
		isInitialized = true; //marks this object as initialized
			
	}
	
	

	/** 
	 * Initializes this prp with secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 * @throws InvalidParameterSpecException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		/*
		 * Creates the relevant bc parameters to pass when inverting or computing.
		 */
		
		//init parameters
		this.secretKey = secretKey;
		this.params = params;
		
		//send the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey, params);
		
		//at the beginning forEncryption is set to true. Init the BC block cipher.
		bcBlockCipher.init(forEncryption, bcParams);
		
		isInitialized = true; //marks this object as initialized
	}
	
	public boolean isInitialized(){
		return isInitialized;
	}
	
	
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}

	public SecretKey getSecretKey() throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		return secretKey;
	}
	
	/**
	 * @return the name of the underlying blockCipher
	 */
	public String getAlgorithmName() {
		return bcBlockCipher.getAlgorithmName();
	}

	/**  
	 * @return the block size of the underlying blockCipher.
	 */
	public int getBlockSize(){
		
		return bcBlockCipher.getBlockSize();
	}

	/** 
	 * Computes the underlying permutation. <p>
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// checks that the offset and length are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the bc block cipher is not already in encryption mode initializes the block cipher with forEncryption=true
		if(forEncryption==false){
			forEncryption = true;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//does the computeBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}
	
	/**
	 * This function is provided in the interface especially for the sub-family PrfVaryingInputLength, which may have variable input length.
	 * Since this is a prp, the input length is fixed with the block size, so this function normally shouldn't be called. 
	 * If the user still wants to use this function, the input length should be the same as the block size. Otherwise, throws an exception.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOffset output offset in the outBytes array to put the result from
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		//the checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset)
		if(inLen==getBlockSize()) //checks that the input length is the same as the block size.
			computeBlock(inBytes, inOffset, outBytes, outOffset);
		else
			throw new IllegalBlockSizeException("Wrong size");
	}
	
	/** 
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which may have variable input/output lengths.
	 * Since both Input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of <code>getBlockSize<code>, otherwise, throws an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		//the checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff)
		if (inLen==outLen && inLen==getBlockSize()) //checks that the lengths are the same as the block size
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
			
	}
	
	/** 
	 * Inverts the underlying permutation.
	 * 
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to put the result from
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) throws UnInitializedException {
		/*
		 * Calls the underlying bc block cipher processBlock. Since we wish to invertBlock we first set the flag
		 * of forEncryption to false.
		 */
		
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		
		// checks that the offsets are correct 
		if ((inOff > inBytes.length) || (inOff+getBlockSize() > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOff > outBytes.length) || (outOff+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//if the bc block cipher is not already in decryption mode init the block cipher with forEncryption=false
		if(forEncryption==true){
			forEncryption = false;
			//init the bcBlockCipher for encryption(true)
			bcBlockCipher.init(forEncryption, bcParams);
		}
		//does the invertBlock
		bcBlockCipher.processBlock(inBytes, inOff, outBytes, outOff);
	}

	
	
	/**
	 * This function is provided in the interface especially for the sub-family PrpVarying, which may have variable input/output lengths.
	 * Since in this case, both input and output variables are fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument <code>len<code> should be the same as 
	 * the result of <code>getBlockSize<code>, otherwise, throws an exception. 
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
		//the checks of the offset and lengths are done in the invertBlock(inBytes, inOff, outBytes, outOff)
		if (len==getBlockSize()) //checks that the length is the same asthe block size
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}


}