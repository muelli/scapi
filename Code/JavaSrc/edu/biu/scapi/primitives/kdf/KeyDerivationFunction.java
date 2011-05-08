/**
 * 
 * A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value 
 * with high entropy (but no other guarantee regarding its distribution). 
 */
package edu.biu.scapi.primitives.kdf;

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
}