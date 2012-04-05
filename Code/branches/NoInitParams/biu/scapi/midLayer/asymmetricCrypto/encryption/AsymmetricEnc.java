package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InitializationException;
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
	 * Sets this asymmetric encryption with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey)throws InvalidKeyException;
	
	/**
	 * Sets this asymmetric encryption with a public key<p> 
	 * In this case the encryption object can be used only for encryption.
	 * @param publicKey
	 */
	public void setKey(PublicKey publicKey)throws InvalidKeyException;
	
	/**
	 * Checks if this AsymmetricEnc object has been previously initialized.<p> 
	 * To initialize the object the init function has to be called with corresponding parameters after construction.
	 * 
	 * @return <code>true<code> if the object was initialized;
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isKeySet();
	
		
	/**
	 * @return the name of this AsymmetricEnc
	 */
	public String getAlgorithmName();
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme.
	 * @param plaintext message to encrypt
	 * @return Ciphertext the encrypted plaintext
	 */
	public Ciphertext encrypt(Plaintext plainText);
	
	/**
	 * Decrypts the given ciphertext using this asymmetric encryption scheme.
	 * @param cipher ciphertext to decrypt
	 * @return Plaintext the decrypted cipher
	 * @throws KeyException 
	 */
	public Plaintext decrypt(Ciphertext cipher) throws KeyException;
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @param keyParams hold the required key size
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey();
		
}
