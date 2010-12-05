/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

/** 
 * @author LabTest
  */
public interface PseudorandomGenerator {
	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secrete key
	 */
	public void init(KeySpec secretKey);

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey
	 * @param params
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this prg
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * The algorithm name
	 */
	public void getAlgorithmName();

	/** 
	 * @param bytein - the single byte to xor
	 */
	public void streamSingleByte(byte bytein);

	/** 
	 * @param in_bytes - the input bytes
	 * @param inOff - input offset
	 * @param len - length
	 * @param outOff - 
	 * @param byteout_bytes
	 */
	public void streamBytes(byte[] in_bytes, int inOff,
			int len, int outOff, byte[] out_bytes);

	/** 
	 * @return the secret key
	 */
	public KeySpec getSecretKeySpec();
}