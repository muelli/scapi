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
 * Adapter class that wraps the Hmac of bouncy castle.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcHMAC implements  Hmac {
	/*
	 * Our class Hmac is an adapter class for the adaptee class HMac of BC.  
	 */
	private HMac hMac;//The underlying wrapped hmac of BC.
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;
	private boolean isInitialized = false;//until init is called set to false.

	/** 
	 * This constructor receives an hashName and build the underlying hmac accoring to it. It can be called from the factory.
	 * @param hashName - the hash function to translate into digest of bc hmac
	 * @throws FactoriesException 
	 */
	public BcHMAC(String hashName) throws FactoriesException {
		
		hMac = new HMac(BCFactory.getInstance().getDigest(hashName));
			
	}

	/**
	 * This constructor gets a SCAPI collision resistant hash to be the underlying hash and retrieves the name of the hash in
	 * order to create the related digest for the BC Hmac this class uses.
	 * @param hash - the underlying collision resistant hash 
	 * @throws FactoriesException, IllegalStateException 
	 */

	public BcHMAC(CollisionResistantHash hash) throws FactoriesException, IllegalStateException {
	
		//first check that the hmac is initialized.
		if(hash.isInitialized()){
			//passes a digest to the hmac.
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
		//no auxiliary parameters for HMAC. Passes the key
		init(secretKey);
	}
	
	/** 
	 * Initializes this hmac with a secret key.
	 * @param secretKey the secret key 
	 */
	public void init(SecretKey secretKey) {
		
		//assigns the key
		this.secretKey = secretKey;
		
		CipherParameters bcParams; 
		//gets the relevant BC cipher parameter
		bcParams = BCParametersTranslator.getInstance().translateParameter((SecretKeySpec)secretKey);
		
		//passes the key parameter to bc hmac
		hMac.init(bcParams);
		
		//sets flag to true. Object is initializing.
		isInitialized = true;
		
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
	 * This function is provided in the interface especially for the sub-family Prp, which have fixed input/output lengths.
	 * Since in this case the input is not fixed, it must be supplied and this function should not be called. 
	 * If the user still calls this function, throws an exception.
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
	 * This function is provided in the interface especially for the sub-family PrfVaryingIOLength, which have varying input/output lengths.
	 * Since in this case the output variable is fixed this function should not normally be called. 
	 * If the user still wants to use this function, the specified argument outLen should be the same as 
	 * the result of getMacSize from BC, otherwise, throws an exception. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to put the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException, UnInitializedException{
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		//the checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff)
		//make sure the output size is correct
		if(outLen==hMac.getMacSize())
			computeBlock(inBytes, inOff, inLen, outBytes, outOff);
		else
			throw new IllegalBlockSizeException("Output size is incorrect");
	}
	
	/**
	 * Computes the function using the secret key. 
	 * The user supplies the input byte array and the offset from 
	 * which to take the data from. Also since the input is not fixed the input length is supplied as well. 
	 * The user also supplies the output byte array as well as the offset. 
	 * The computeBlock function will put the output starting at the offset. 
	 * 
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOffset input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOffset output offset in the outBytes array to put the result from
	 * @throws UnInitializedException 
	 */

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws UnInitializedException {
		if(!isInitialized()){
			throw new UnInitializedException();
		}
		// checks that the offset and length are correct 
		if ((inOffset > inBytes.length) || (inOffset+inLen > inBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOffset > outBytes.length) || (outOffset+getBlockSize() > outBytes.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//passes the input bytes to update
		hMac.update(inBytes, inOffset, inLen);
		
		//gets the output results through doFinal
		hMac.doFinal(outBytes, outOffset);
	}

}