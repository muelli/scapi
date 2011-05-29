/**
 * 
 */
package edu.biu.scapi.primitives.PerfectUniversalHash;

import java.security.spec.AlgorithmParameterSpec;

/** 
  * @author LabTest
 */
public abstract class PerfectUniversalAbs implements PerfectUniversalHash {
	protected AlgorithmParameterSpec params;
	protected boolean isInitialized = true;//most target collision resistant hash functions do not need to call init
										   //if a certain hash does need to pass some parameters in init, it must set this
										   //flag to false in the constructor and to true in the init function.

	/** 
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params) {

		isInitialized = true;
		this.params = params;
	}

	/**
	 * 
	 * @return the flag isInitialized
	 */
	public boolean isInitialized(){
		return isInitialized;
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