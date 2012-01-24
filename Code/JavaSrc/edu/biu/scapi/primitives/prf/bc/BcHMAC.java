package edu.biu.scapi.primitives.prf.bc;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.macs.HMac;


import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.SecretKeyGeneratorUtil;
import edu.biu.scapi.midLayer.symmetricCrypto.keys.SymKeyGenParameterSpec;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.prf.Hmac;
import edu.biu.scapi.tools.Factories.BCFactory;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;



/** 
 * Adapter class that wraps the Hmac of bouncy castle.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcHMAC implements Hmac {
	/*
	 * Our class Hmac is an adapter class for the adaptee class HMac of BC.  
	 */
	private HMac hMac;									//The underlying wrapped hmac of BC.
	private AlgorithmParameterSpec params = null;
	private SecretKey secretKey = null;
	private boolean isInitialized = false;				//until init is called set to false.
	private SecureRandom random = new SecureRandom();	//source of randomness used in key generation

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
	 * @throws FactoriesException
	 * @throws UnInitializedException if the given hash is not initialized
	 */

	public BcHMAC(CryptographicHash hash) throws FactoriesException, UnInitializedException {
	
		//first check that the hmac is initialized.
		if(hash.isInitialized()){
			//passes a digest to the hmac.
			hMac = new HMac(BCFactory.getInstance().getDigest(hash.getAlgorithmName()));
		}
		else{//the user must pass an initialized object, otherwise throw an exception
			throw new UnInitializedException("argument hash must be initialized");
		}
	}
	
	/** 
	 * Initializes this hmac with the secret key and the auxiliary parameters
	 * @param secretKey secret key 
	 * @param params algorithm parameter
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params)  {
		//call the second init(SecretKey secretKey, AlgorithmParameterSpec params) function with default source of randomness
		init(secretKey, params, new SecureRandom());
	}
	
	/** 
	 * Initializes this hmac with the secret key and the auxiliary parameters
	 * @param secretKey secret key 
	 * @param params algorithm parameter
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params, SecureRandom rnd)  {
		//no auxiliary parameters for HMAC. Passes the key and the random
		init(secretKey, rnd);
		
	}
	
	/** 
	 * Initializes this hmac with a secret key.
	 * @param secretKey the secret key 
	 */
	public void init(SecretKey secretKey) {
		//call the second init function with default source of randomness
		init(secretKey, new SecureRandom());
		
	}
	
	/** 
	 * Initializes this hmac with a secret key.
	 * @param secretKey the secret key 
	 */
	public void init(SecretKey secretKey, SecureRandom rnd) {
		
		//assigns the key
		this.secretKey = secretKey;
		
		CipherParameters bcParams; 
		//gets the relevant BC cipher parameter
		bcParams = BCParametersTranslator.getInstance().translateParameter(secretKey);
		
		//passes the key parameter to bc hmac
		hMac.init(bcParams);
		
		//set the random member with the given random
		random = rnd;
		
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
	
	/** 
	 * @return the name from BC hmac
	 */
	public String getAlgorithmName() {
		
		return hMac.getAlgorithmName();
	}

	/**
	 * @return the block size of the BC hmac in bytes
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
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keySize SymKeyGenParameterSpec contains the required secret key size in bits 
	 * @return the generated secret key
	 * @throws UnInitializedException if this object is not initialized
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keySize){
		//call the generateKey function that gets a random with the default secureRandom
		return generateKey(keySize, random);
	}
	
	/**
	 * Generates a secret key to initialize this mac object.
	 * @param keySize SymKeyGenParameterSpec contains the required secret key size in bits 
	 * @return the generated secret key
	 * @throws UnInitializedException if this object is not initialized
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keySize, SecureRandom rnd){
		if(!(keySize instanceof SymKeyGenParameterSpec)){
			throw new IllegalArgumentException("keySize should be instance of SymKeyGenParameterSpec");
		}
		
		//generates key according to the given key size, this algorithm name and random
		return SecretKeyGeneratorUtil.generateKey(((SymKeyGenParameterSpec) keySize).getEncKeySize(), getAlgorithmName(), rnd);
	}
	
	/**
	 * Returns the input block size in bytes
	 * @return the input block size
	 */
	public int getMacSize(){
		return getBlockSize();
	}
	
	/**
	 * Computes the hmac operation on the given msg and return the calculated tag
	 * @param msg the message to operate the mac on
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message
	 * @return byte[] the return tag from the mac operation
	 * @throws UnInitializedException if this object is not initialized
	 */
	public byte[] mac(byte[] msg, int offset, int msgLen) throws UnInitializedException{
		//creates the tag
		byte[] tag = new byte[getMacSize()];
		//computes the hmac operation
		computeBlock(msg, offset, msgLen, tag, 0);
		//returns the tag
		return tag;
	}
	
	/**
	 * verifies that the given tag is valid for the given message
	 * @param msg the message to compute the mac on to verify the tag
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @param tag the tag to verify
	 * @return true if the tag is the result of computing mac on the message. false, otherwise.
	 * @throws UnInitializedException if this object is not initialized
	 */
	public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag) throws UnInitializedException{
		//if the tag size is not the mac size - returns false
		if (tag.length != getMacSize()){
			return false;
		}
		//calculates the mac on the msg to get the real tag
		byte[] macTag = mac(msg, offset, msgLength);
		
		//compares the real tag to the given tag
		//for code-security reasons, the comparison is fully performed. that is, even if we know 
		//already after the first few bits that the tag is not equal to the mac, we continue the 
		//checking until the end of the tag bits
		boolean equal = true;
		int length = macTag.length;
		for (int i=0;i<length; i++){
			if (macTag[i] != tag[i]){
				equal = false;
			}
		}
		return equal;	
	}
	
	/**
	 * Adds the byte array to the existing message to mac.
	 * @param msg the message to add
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLen the length of the message
	 */
	public void update(byte[] msg, int offset, int msgLen){
		//calls the underlying hmac update
		hMac.update(msg, offset, msgLen);
	}
	
	/**
	 * Completes the mac computation and puts the result tag in the tag array.
	 * @param msg the end of the message to mac
	 * @param offset the offset within the message array to take the bytes from
	 * @param msgLength the length of the message
	 * @return the result tag from the mac operation
	 */
	public byte[] doFinal(byte[] msg, int offset, int msgLength){
		//updates the last msg block
		update(msg, offset, msgLength);
		//creates the tag
		byte[] tag = new byte[getMacSize()];
		//calls the underlying hmac doFinal function
		hMac.doFinal(tag, 0);
		//returns the tag
		return tag;
	}
	
	

}