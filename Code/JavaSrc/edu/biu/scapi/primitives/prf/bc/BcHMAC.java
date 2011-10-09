/**
 * An adapter class that wrapps the Hmac of bouncy castle.
 */
package edu.biu.scapi.primitives.prf.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.macs.HMac;


import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.hash.CollisionResistantHash;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.tools.Factories.BCFactory;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;



	/** 
	 * @author LabTest
	 */
public final class BcHMAC implements  Hmac {
	
	private HMac hMac;//The underlying wrapped hmac of BC.
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;
	private boolean isInitialized = false;//until isInitialized() is called set to false.

	/** 
	 * A constructor that can be called from the factory
	 * @param hashName - the hash function to translate into digest of bc hmac
	 * @throws FactoriesException 
	 */
	public BcHMAC(String hashName) throws FactoriesException {
		
		hMac = new HMac(BCFactory.getInstance().getDigest(hashName));
		
		
	}

	/**
	 * A constructor that gets a SCAPI collision resistant hash and retrieves the name of the hash in
	 * order to crete the related digest for the BC Hmac this class uses.
	 * @param hash - the underlying collision resistant hash 
	 * @throws FactoriesException, IllegalStateException 
	 */

	public BcHMAC(CollisionResistantHash hash) throws FactoriesException, IllegalStateException {
	
		//first check that the hmac is initialized.
		if(hash.isInitialized()){
			//pass a digest to the KDF.
			hMac = new HMac(BCFactory.getInstance().getDigest(hash.getAlgorithmName()));
		}
		else{//the user must pass an initialized object, otherwise throw an exception
			throw new IllegalStateException("argument hash must be initialized");
		}
	}
	
	/** 
	 * Initializes this hmac with the secret key and the auxiliary parameters
	 * @param secretKey secret key 
	 * @param params algorithm parameter
	 * @throws InvalidParameterSpecException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		//no auxiliary parameters for HMAC. Pass the key
		init(secretKey);
	}
	
	/** 
	 * Initializes the bc underlying hmac
	 * @param secretKey the secret key to convert to bc key parameter
	 */
	public void init(SecretKey secretKey) {
		
		//set flag to true. Object is initializing.
		isInitialized = true;
		
		//assign the key
		this.secretKey = secretKey;
		
		CipherParameters bcParams; 
		//get the relevant cipher parameter
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//pass the key parameter to bc hmac
		hMac.init(bcParams);
		
	}
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return isInitialized;
	}

	/** 
	 * Since the input is not fixed, it must be supplied. This function should not be called. 
	 * If the user still calls this function, throw an exception.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException, UnInitializedException{
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		throw new IllegalBlockSizeException("Size of input is not specified");
	}
	
	/**
	 * 
	 * Since both output variable is fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument outLen should be the same as 
	 * the result of getMacSize from BC, otherwise, throw an exception. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException, UnInitializedException{
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
		//make sure the output size is correct
		if(outLen==hMac.getMacSize())
			computeBlock(inBytes, inOff, inLen, outBytes, outOff);
		else
			throw new IllegalBlockSizeException("Output size is incorrect");
	}
	
	/**
	 * 
	 * Computes the function using the secret key. The user supplies the input byte array and the offset from 
	 * which to take the data from. Also since the input is not fixed the input is supplied as well. 
	 * The user also supplies the output byte array as well as the offset. 
	 * The computeBlock function will put the output starting at the offset. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOffset output offset in the outBytes array to take the result from
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException, UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		/* check that the offset and length are correct */
		if ((inOffset > inBytes.length) || (inOffset+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("input buffer too short");
		}
		if ((outOffset > outBytes.length) || (outOffset+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("output buffer too short");
		}
		//pass the input bytes to update
		hMac.update(inBytes, inOffset, inLen);
		
		//get the output results through doFinal
		hMac.doFinal(outBytes, outOffset);
	}
	

	

	/** 
	 * @return the name from BC hmac
	 */
	public String getAlgorithmName() {
		
		return hMac.getAlgorithmName();
	}

	/**
	 * @return the block size of the BC hmac
	 * @throws UnInitializedException 
	 */
	public int getBlockSize(){
		return hMac.getMacSize();
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