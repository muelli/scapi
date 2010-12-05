/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;


/** 
 * @author LabTest
 */
public abstract class PseudorandomFunctionAbs implements PseudorandomFunction {
	
	protected KeySpec secretKeySpec = null;//secret key
	protected AlgorithmParameterSpec params = null;//algorithm parameters

	/** 
	 * @param secretKey
	 * @param params
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params) {
		
		secretKeySpec = secretKey;
		this.params = params;
	}

	/** 
	 * @param secretKey
	 */
	public void init(KeySpec secretKey) {
		secretKeySpec = secretKey;
	}

	/** 
	 * @return
	 */
	public String getAlgorithmName() {
		return null;
	}

	/** 
	 * @return
	 */
	public int getBlockSize() {
		return 0;
	}

	/** 
	 * @param inBytes - input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public abstract void computetBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff); {}

	/** 
	 * @return
	 */
	public AlgorithmParameterSpec getParams() {
		return params;
	}

	/** 
	 * @return
	 */
	public KeySpec getSecretKeySpec() {
		return secretKeySpec;
	}
}