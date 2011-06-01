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
	 * Initialize this perfect universal hash with the auxiliary parameters 
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
	 * @return the parameter spec of this perfect universal hash
	 */
	public AlgorithmParameterSpec getParams() {

		return params;
	}
	
}