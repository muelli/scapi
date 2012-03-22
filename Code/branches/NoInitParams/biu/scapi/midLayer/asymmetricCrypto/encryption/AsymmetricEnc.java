package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

/**
 * General interface for asymmetric encryption. Each class of this family must implement this interface. <p>
 * 
 * Asymmetric encryption refers to a cryptographic system requiring two separate keys, one to encrypt the plaintext, and one to decrypt the ciphertext. 
 * Neither key will do both functions. 
 * One of these keys is public and the other is kept private. 
 * If the encryption key is the one published then the system enables private communication from the public to the decryption key's owner.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface AsymmetricEnc {

	/**
	 * Initializes this asymmetric encryption with public key, private key and params.
	 * @param publicKey
	 * @param privateKey
	 * @param params
	 * @throws FactoriesException 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params) throws FactoriesException, IllegalArgumentException, IOException;
	
	/**
	 * Initializes this asymmetric encryption with public key, private key, params and source of randomness.
	 * @param publicKey
	 * @param privateKey
	 * @param params
	 * @param random source of randomness
	 * @throws FactoriesException 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params, SecureRandom random) throws FactoriesException, IllegalArgumentException, IOException;
	
	/**
	 * Initializes this asymmetric encryption with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey);
	
	/**
	 * Initializes this asymmetric encryption with public key, private keyand source of randomness.
	 * @param publicKey
	 * @param privateKey
	 * @param random source of randomness
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, SecureRandom random);
	
	/**
	 * Initializes this asymmetric encryption with public key and params.
	 * If this function is called, this asymmetric encryption can encrypt messages but can not decrypt any cipher text.
	 * @param publicKey
	 * @param params
	 * @throws FactoriesException 
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params) throws FactoriesException, IOException;
	
	/**
	 * Initializes this asymmetric encryption with public key, params and source of randomness.
	 * If this function is called, this asymmetric encryption can encrypt messages but can not decrypt any cipher text.
	 * @param publicKey
	 * @param params
	 * @param random source of randomness
	 * @throws FactoriesException
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params, SecureRandom random) throws FactoriesException, IOException;
	
	/**
	 * Initializes this asymmetric encryption with public key.
	 * If this function is called, this asymmetric encryption can encrypt messages but can not decrypt any cipher text.
	 * @param publicKey
	 */
	public void init(PublicKey publicKey);
	
	/**
	 * Initializes this asymmetric encryption with public key and source of randomness.
	 * If this function is called, this asymmetric encryption can encrypt messages but can not decrypt any cipher text.
	 * @param publicKey
	 * @param random source of randomness
	 */
	public void init(PublicKey publicKey, SecureRandom random);
	
	/**
	 * Checks if this AsymmetricEnc object has been previously initialized.<p> 
	 * To initialize the object the init function has to be called with corresponding parameters after construction.
	 * 
	 * @return <code>true<code> if the object was initialized;
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isInitialized();
	
	/**
	 * @return the algorithmParameterSpec used in this object
	 * @throws UnInitializedException if this object is not initialized
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException;
	
	/**
	 * @return the name of this AsymmetricEnc
	 */
	public String getAlgorithmName();
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme.
	 * @param plaintext message to encrypt
	 * @return Ciphertext the encrypted plaintext
	 * @throws UnInitializedException 
	 */
	public Ciphertext encrypt(Plaintext plainText) throws UnInitializedException;
	
	/**
	 * Decrypts the given ciphertext using this asymmetric encryption scheme.
	 * @param cipher ciphertext to decrypt
	 * @return Plaintext the decrypted cipher
	 * @throws UnInitializedException 
	 */
	public Plaintext decrypt(Ciphertext cipher) throws UnInitializedException;
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @param keyParams hold the required key size
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @param keyParams hold the required key size
	 * @param random source of randomness
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException;
	

	
}
