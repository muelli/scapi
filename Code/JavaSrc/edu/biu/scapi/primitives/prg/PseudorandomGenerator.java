/**
 * 
 */
package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

/** 
 * @author LabTest
  */
public interface PseudorandomGenerator {
	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secret key
	 */
	public void init(SecretKey secretKey);

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey
	 * @param params
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this prg
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName();

	/**
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - length
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset, int outlen);

	/** 
	 * @return the secret key
	 */
	public SecretKey getSecretKey();
}