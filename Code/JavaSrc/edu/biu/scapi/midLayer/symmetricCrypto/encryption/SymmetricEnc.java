package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SymmetricEnc {

	public void init(SecretKey secretKey);
	public void init(SecretKey secretKey, SecureRandom random);
	public void init(SecretKey secretKey, AlgorithmParameterSpec params);
	public void init(SecretKey secretKey, AlgorithmParameterSpec params, SecureRandom random);
	public boolean isInitialized();
	public AlgorithmParameterSpec getParams();
	public String getAlgorithmName();
	public SecretKey generateKey(AlgorithmParameterSpec keySize );
	public SecretKey generateKey(AlgorithmParameterSpec keySize, SecureRandom random );
	public Ciphertext encrypt(Plaintext plaintext);
	public Ciphertext encrypt(Plaintext plaintext, byte[] iv);
	public Plaintext decrypt(Ciphertext ciphertext);
	
	
}
