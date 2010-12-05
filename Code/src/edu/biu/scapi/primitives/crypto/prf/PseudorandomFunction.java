/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;


/** 
 * @author LabTest
 */
public interface PseudorandomFunction {
	/**
	 * Initializes this prf with the secret key
	 * @param secretKey - the secrete key
	 *  */
	public void init(KeySpec secretKey);

	/** 
	 * Initializes this prf with the secret key and the auxiliary parameters
	 * @param secretKey - secret key
	 * @param params - algorithm parameters
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this prf
	 */
	public AlgorithmParameterSpec getParams();

	
	/** 
	 * @return the secret key
	 */
	public KeySpec getSecretKeySpec();


	/** 
	 * @return The algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @return
	 */
	public int getBlockSize();

	/** 
	 * @param inBytes - input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public void computetBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff);
}