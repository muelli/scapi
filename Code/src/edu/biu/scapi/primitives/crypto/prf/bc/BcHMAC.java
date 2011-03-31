/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf.bc;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;


import edu.biu.scapi.primitives.crypto.prf.Hmac;
import edu.biu.scapi.tools.Factories.BCFactory;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;



	/** 
	 * @author LabTest
	 */
public class BcHMAC implements  Hmac {
	
	private HMac hMac;//The underlying wrapped hmac of BC.
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;

	/** 
	 * @param hash - the hash function to translate into digest of bc hmac
	 */
	public BcHMAC(String hash) {
		
		Digest digest = null;
		digest = BCFactory.getInstance().getDigest(hash);
		
		
		//create the Hmac of BC
		hMac = new HMac(digest);
		
		
	}

	/** 
	 * @param secretKey - secret key 
	 * @param params - algorithm parameter
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {
		
		//no auxiliary parameters for HMAC. Pass the key
		init(secretKey);
	}

	/** 
	 * @param inBytes - input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException{
		
		throw new IllegalBlockSizeException("Size of input is not specified");
	}
	
	/**
	 * 
	 * computetBlock : 
	 * 
	 * 
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException{
		
		//make sure the output size is correct
		if(outLen==hMac.getMacSize())
			computeBlock(inBytes, inOff, inLen, outBytes, outOff);
		else
			throw new IllegalBlockSizeException("Output size is incorrect");
	}
	
	/**
	 * 
	 * computetBlock : 
	 * 
	 * 
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException {
		
		//pass the input bytes to update
		hMac.update(inBytes, inOffset, inLen);
		
		//get the output results through doFinal
		hMac.doFinal(outBytes, outOffset);
	}
	

	/** 
	 * Initializes the bc underlying hmac
	 * @param secretKey - the secret key to convert to bc key parameter
	 */
	public void init(SecretKey secretKey) {
		
		//assign the key
		this.secretKey = secretKey;
		
		CipherParameters bcParams; 
		//get the relevant cipher parameter
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//pass the key parameter to bc hmac
		hMac.init(bcParams);
		
	}

	/** 
	 * @return - the name from bc hmac
	 */
	public String getAlgorithmName() {
		
		return hMac.getAlgorithmName();
	}

	/**
	 * @return - the block size of the BC hmac
	 */
	public int getBlockSize() {
		
		return hMac.getMacSize();
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