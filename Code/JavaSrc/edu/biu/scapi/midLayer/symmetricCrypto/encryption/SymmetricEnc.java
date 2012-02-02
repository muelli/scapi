package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.securityLevel.Eav;
import edu.biu.scapi.securityLevel.Indistinguishable;

/**
 * This is the main interface for the Symmetric Encryption family.<p> 
 * The symmetric encryption family of classes implements three main functionalities that correspond to the cryptographer’s language 
 * in which an encryption scheme is composed of three algorithms:<p>
 * 	1.	Generation of the key.<p>
 *	2.	Encryption of the plaintext.<p>
 *	3.	Decryption of the ciphertext.<p>
 * 
 * Any symmetric encryption scheme belongs by default at least to the Eavsdropper Security Level and to the Indistinguishable Security Level.
 *   
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SymmetricEnc extends Eav, Indistinguishable{

	public void init(SecretKey secretKey) throws InvalidKeyException;
	public void init(SecretKey secretKey, SecureRandom random) throws InvalidKeyException;
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidParameterSpecException;
	public void init(SecretKey secretKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidParameterSpecException;
	public boolean isInitialized();
	public AlgorithmParameterSpec getParams() throws UnInitializedException;
	public String getAlgorithmName();
	public SecretKey generateKey(AlgorithmParameterSpec keySize ) throws InvalidParameterSpecException;
	public SecretKey generateKey(AlgorithmParameterSpec keySize, SecureRandom random ) throws InvalidParameterSpecException;
	public SymmetricCiphertext encrypt(Plaintext plaintext) throws UnInitializedException;
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv)throws UnInitializedException, IllegalBlockSizeException;
	public Plaintext decrypt(Ciphertext ciphertext) throws UnInitializedException;
	
	
}
