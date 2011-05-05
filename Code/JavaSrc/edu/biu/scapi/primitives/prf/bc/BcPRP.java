/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf.bc;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import edu.biu.scapi.primitives.crypto.prf.PrpFixed;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/** 
 * @author LabTest
 * 
 * A general adapter class of PrpFixed for Bouncy Castle. 
 * This class implements all the functionality by passing requests to the adaptee interface BlockCipher. 
 * A concrete PRP such as AES represented by the class BcAES only passes the AESEngine object in the constructor 
 * to the base class. 
 */
public abstract class BcPRP implements PrpFixed{
	
	private BlockCipher bcBlockCipher = null;//bc block cipher
	private CipherParameters bcParams = null;//bc paramters
	private boolean forEncryption = true;//set for true. If decryption is needed the flag will be set to false. DO NOT CHANGE SINCE THE INIT IS FOR TRUE
	private SecretKey secretKey = null;
	private AlgorithmParameterSpec params = null;
	

	/** 
	 * @param bcBlockCipher - the underlying bc block cipher
	 */
	public BcPRP(BlockCipher bcBlockCipher) {
		
		this.bcBlockCipher = bcBlockCipher;
	}

	
	/** 
	 */
	public String getAlgorithmName() {
		
		return bcBlockCipher.getAlgorithmName();
	}

	/** 
	 */
	public int getBlockSize() {
		return bcBlockCipher.getBlockSize();
	}

	/** 
	 * computeBlock : call the underlying bc block cipher processBlock. Since we wish to computeBlock we first set the flag
	 * of forEncryption to true.
	 * @param inBytes- input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) {
		
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
	 * computetBlock : Call computeBlock if the input length is correct. Otherwise, throw an exception.
	 * 
	 * 
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException {
		
		if(inLen==getBlockSize())
			computeBlock(inBytes, inOffset, outBytes, outOffset);
		else
			throw new IllegalBlockSizeException("Wrong size");
	}
	

	/** 
	 * invertBlock : call the underlying bc block cipher processBlock. Since we wish to invertBlock we first set the flag
	 * of forEncryption to false.
	 * @param inBytes- input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,	int outOff) {
		
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
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey - secret key
	 */
	public void init(SecretKey secretKey) {
		
		//init parameters
		this.secretKey = secretKey;
		
		//get the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		bcBlockCipher.init(true, bcParams);
			
	}

	/** 
	 * Creates the relevant bc parameters to pass when inverting or computing.
	 * @param secretKey - secret key
	 * @param params - algorithm parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//init parameters
		this.secretKey = secretKey;
		this.params = params;
		
		//send the parameters converted to bc.
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey, params);
		
		bcBlockCipher.init(true, bcParams);
		
	}
	
	/**
	 *  since both Input and output variables are fixed this function should not normally be call. 
	 * If the user still wants to use this function, the specified argument len should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception. 
	 * @param inBytes - input bytes to invert
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param len - the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException {
		
		if (len==getBlockSize())
			invertBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
		
	}

	/** 
	 * computeBlock - since both Input and output variables are fixed this function should not normally be call. 
	 * If the user still wants to use this function, the input and output lengths should be the same as 
	 * the result of getBlockSize, otherwise, throw an exception.
	 * @param inBytes - input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen,
			byte[] outBytes, int outOff, int outLen)
			throws IllegalBlockSizeException {
		
		if (inLen==outLen && inLen==getBlockSize())
			computeBlock(inBytes, inOff, outBytes, outOff);
		else 
			throw new IllegalBlockSizeException("Wrong size");
			
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
}