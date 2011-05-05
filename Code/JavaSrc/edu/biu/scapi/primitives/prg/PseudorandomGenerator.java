/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

/** 
 * @author LabTest
  */
public interface PseudorandomGenerator {
	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secrete key
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
	 * @return The algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @param bytein - the single byte to xor
	 */
	public void streamSingleByte(byte bytein);

	/** 
	 * @param inBytes - the input bytes
	 * @param inOff - input offset
	 * @param len - length
	 * @param outBytes - output bytes. The result of streaming the input bytes.
	 * @param outOff - output offset
	 */
	public void streamBytes(byte[] inBytes, int inOff,
			int len, byte[] outBytes, int outOff);

	/** 
	 * @return the secret key
	 */
	public SecretKey getSecretKey();
}