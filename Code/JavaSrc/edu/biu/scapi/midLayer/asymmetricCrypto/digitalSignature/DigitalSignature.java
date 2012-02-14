package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;

/**
 * General interface for digital signatures. Each class of this family must implement this interface. <p>
 * 
 * A digital signature is a mathematical scheme for demonstrating the authenticity of a digital message or document. 
 * A valid digital signature gives a recipient reason to believe that the message was created by a known sender, 
 * and that it was not altered in transit.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DigitalSignature {

	/**
	 * Initializes this digital signature with public key, private key and params.
	 * @param publicKey
	 * @param privateKey
	 * @param params
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params);
	
	/**
	 * Initializes this digital signature with public key, private key, params and source of randomness.
	 * @param publicKey
	 * @param privateKey
	 * @param params
	 * @param random source of randomness
	 * @throws FactoriesException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params, SecureRandom random);
	
	/**
	 * Initializes this digital signature with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey);
	
	/**
	 * Initializes this digital signature with public key, private key and source of randomness.
	 * @param publicKey
	 * @param privateKey
	 * @param random source of randomness
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey, SecureRandom random);
	
	/**
	 * Initializes this digital signature with public key and params.
	 * If this function is called, this digital signature can verify signatures but can not sign any messages.
	 * @param publicKey
	 * @param params 
	 * @throws IOException 
	 * @throws FactoriesException 
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params) throws FactoriesException, IOException;
	
	/**
	 * Initializes this digital signature with public key, params and source of randomness.
	 * If this function is called, this digital signature can verify signatures but can not sign any messages.
	 * @param publicKey
	 * @param params
	 * @param random source of randomness
	 * @throws FactoriesException
	 */
	public void init(PublicKey publicKey, AlgorithmParameterSpec params, SecureRandom random) throws FactoriesException, IOException;
	
	/**
	 * Initializes this digital signature with public key.
	 * If this function is called, this digital signature can verify signatures but can not sign any messages.
	 * @param publicKey
	 */
	public void init(PublicKey publicKey);
	
	/**
	 * Initializes this digital signature with public key and source of randomness.
	 * If this function is called, this digital signature can verify signatures but can not sign any messages.
	 * @param publicKey
	 * @param random source of randomness
	 */
	public void init(PublicKey publicKey, SecureRandom random);
	
	/**
	 * Checks if this DigitalSignature object has been previously initialized.<p> 
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
	 * Updates the message to sign
	 * @param msg the byte array to add the the signing msg
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 */
	public void update(byte[] msg, int offset, int length);
	
	/**
	 * Completes updating of the message and signs it.
	 * @param msg the byte array to add the the signing msg
	 * @param offset the place in the msg to take the bytes from
	 * @param length the length of the msg
	 * @return the signature
	 * @throws CryptoException 
	 * @throws DataLengthException 
	 */
	public byte[] doFinal(byte[] msg, int offset, int length) throws DataLengthException, CryptoException;
	/**
	 * Signs the given message
	 * @return the signatures from the msg signing
	 * @throws CryptoException 
	 * @throws DataLengthException 
	 */
	public byte[] sign(byte[] msg, int offset, int length) throws DataLengthException, CryptoException;
	
	/**
	 * Verifies the given signatures.
	 * @param signature to verify
	 * @return true if the signature is valid. false, otherwise.
	 */
	public boolean verify(byte[] signature);

	/**
	 * Generates public and private keys for this digital signature.
	 * @param keyParams hold the required key parameters
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this digital signature.
	 * @param keyParams hold the required key parameters
	 * @param random source of randomness
	 * @return KeyPair holding the public and private keys
	 * @throws InvalidParameterSpecException 
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams, SecureRandom random) throws InvalidParameterSpecException;
}
