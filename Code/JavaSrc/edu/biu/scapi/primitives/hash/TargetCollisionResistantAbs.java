/**
 * 
 */
package edu.biu.scapi.primitives.hash;

import java.security.spec.AlgorithmParameterSpec;

/** 
 * @author LabTest
 */
public abstract class TargetCollisionResistantAbs implements
		TargetCollisionResistant {
	
	protected AlgorithmParameterSpec params;
	protected boolean isInitialized = true;//most target collision resistant hash functions do not need to call init
										   //if a certain hash does need to pass some parameters in init, it must set this
							               //flag to false in the constructor and to true in the init function.

	/** 
	 * Initializes this target collision resistant hash with the auxiliary parameters.
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
	 * @return the parameter spec of this target collision resistant hash
	 */
	public AlgorithmParameterSpec getParams() {
		return params;
	}

}