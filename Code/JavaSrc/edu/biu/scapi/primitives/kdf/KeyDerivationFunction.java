package edu.biu.scapi.primitives.kdf;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * General interface of key derivation function. Every class in this family should implement this interface. <p>
 * A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value 
 * with high entropy (but no other guarantee regarding its distribution). 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface KeyDerivationFunction {
	
	/**
	 * Initializes this kdf with the secret key. The initialization is for the underlying object the KDF used.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 *  */
	public void init(SecretKey secretKey) throws InvalidKeyException;

	/** 
	 * Initializes this kdf with the secret key and the auxiliary parameters. The initialization is for the underlying object the KDF used.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException;
	
	/**
	 * An object trying to use an instance of kdf needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized();
	
	/** 
	 * Generates a new secret key from the given seed and IV.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param len the required output key length
	 * @param iv info for the key generation
	 * @return secret key the generated key
	 * @throws UnInitializedException if this object is not initialized
	 */
	public SecretKey generateKey(SecretKey seedForGeneration, int outLen,  byte[] iv) throws UnInitializedException;
	
	/** 
	 * Generates a new secret key from the given seed.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param len the required output key length
	 * @return secret key the generated key
	 * @throws UnInitializedException if this object is not initialized
	 */
	public SecretKey generateKey(SecretKey seedForGeneration, int outLen) throws UnInitializedException;
	
	/** 
	 * Generates a new secret key from the given seed.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param inOff the offset within the seedForGeneration to take the bytes from
	 * @param inLen the length of the seed
	 * @param outKey the array to put the generated key bytes
	 * @param outoff the offset within the output array to put the generated key bytes from
	 * @param outlen the required output key length
	 * @throws UnInitializedException if this object is not initialized
	 */
	public void generateKey(byte[] seedForGeneration, int inOff, int inLen, byte[] outKey, int outOff, int outLen) throws UnInitializedException;
	
	/** 
	 * Generates a new secret key from the given seed and iv.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param inOff the offset within the seedForGeneration to take the bytes from
	 * @param inLen the length of the seed
	 * @param outKey the array to put the generated key bytes
	 * @param outoff the offset within the output array to put the generated key bytes from
	 * @param outlen the required output key length
	 * @param iv info for the key generation
	 * @throws UnInitializedException if this object is not initialized
	 */
	public void generateKey(byte[] seedForGeneration, int inOff, int inLen, byte[] outKey, int outOff, int outLen, byte[] iv) throws UnInitializedException;
}