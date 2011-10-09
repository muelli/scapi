/**
 * 
 */
package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

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
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException;

	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName();

	/**
	 * @param outBytes - output bytes. The result of streaming the bytes.
	 * @param outOffset - output offset
	 * @param outlen - length
	 * @throws UnInitializedException 
	 */
	public void getPRGBytes(byte[] outBytes, int outOffset, int outlen) throws UnInitializedException;

	/** 
	 * @return the secret key
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException;
}