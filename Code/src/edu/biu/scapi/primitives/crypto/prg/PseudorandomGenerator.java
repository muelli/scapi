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
	 * @param secretKey
	 */
	public void init(KeySpec secretKey);

	/** 
	 * @param secretKey
	 * @param params
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params);

	/** 
	 * @return
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 */
	public void getAlgorithmName();

	/** 
	 * @param _byte
	 */
	public void streamSingleByte(byte bytein);

	/** 
	 * @param bytein_bytes
	 * @param intinOff
	 * @param intlen
	 * @param intoutOff
	 * @param byteout_bytes
	 */
	public void streamBytes(byte[] in_bytes, int inOff,
			int len, int outOff, byte[] out_bytes);

	/** 
	 * @return
	 */
	public KeySpec getSecretKeySpec();
}