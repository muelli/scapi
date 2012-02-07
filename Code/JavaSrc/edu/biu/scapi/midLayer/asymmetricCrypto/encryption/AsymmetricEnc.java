/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.AsymKeyGenParameterSpec;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.securityLevel.*;


/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface AsymmetricEnc extends Cpa, Indistinguishable {
	public void init(PublicKey publicKey);
	public void init(PublicKey publicKey, SecureRandom random);
	public void init(PublicKey publicKey, PrivateKey privateKey);
	public void init(PublicKey publicKey, PrivateKey privateKey, SecureRandom random);
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params, SecureRandom random);
	public void init(PublicKey publicKey, PrivateKey privateKey, AlgorithmParameterSpec params);
	public void init(PublicKey publicKey, AlgorithmParameterSpec params);
	public void init(PublicKey publicKey, AlgorithmParameterSpec params, SecureRandom random);
	public Ciphertext encrypt(Plaintext plaintext);
	public Plaintext decrypt (Ciphertext ciphertext);
	public KeyPair generateKey(AsymKeyGenParameterSpec keyParams, SecureRandom random);
	public KeyPair generateKey(SecureRandom random);
	
}
