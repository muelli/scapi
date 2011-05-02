/**
 * 
 */
package edu.biu.scapi.primitives.crypto.PerfectUniversalHash;

import java.security.spec.AlgorithmParameterSpec;

/** 
  * @author LabTest
 */
public abstract class PerfectUniversalAbs implements PerfectUniversalHash {
	protected AlgorithmParameterSpec params;

	/** 
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @return
	 */
	public AlgorithmParameterSpec getParams() {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/** 
	 * @return
	 */
	public int geInputSize() {
		// begin-user-code
		// TODO Auto-generated method stub
		return 0;
		// end-user-code
	}

	/** 
	 * @return
	 */
	public int geOutputSize() {
		// begin-user-code
		// TODO Auto-generated method stub
		return 0;
		// end-user-code
	}

	/**
	 * 
	 */
	public String getAlgorithmName() {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}

	/**
	 * 
	 */
	public void compute(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
}