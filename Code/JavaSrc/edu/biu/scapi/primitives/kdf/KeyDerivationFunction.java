/**
 * 
 * A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value 
 * with high entropy (but no other guarantee regarding its distribution). 
 */
package edu.biu.scapi.primitives.kdf;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

/** 
  * @author LabTest
 */
public interface KeyDerivationFunction {
	/** 

	 * @param key
	 * @param len
	 * @return
	 */
	public SecretKey generateKey(SecretKey key, int outLen,  byte[] iv);
	public SecretKey generateKey(SecretKey key, int outLen);
	public void generateKey(byte[] inKey, int inOff, int inLen, byte[] outKey, int outOff, int outLen);
	
	/**
	 * Initializes this krf with the secret key.
	 * @param secretKey the secrete key
	 *  */
	public void init(SecretKey secretKey);

	/** 
	 * Initializes this krf with the secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params);
	
	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized();
}