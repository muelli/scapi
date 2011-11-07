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
	protected boolean isInitialized = false;

	/** 
	 * Initializes this target collision resistant hash with the auxiliary parameters.
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params) {
		
		isInitialized = true;
		this.params = params;
	}
	
	/** 
	 * Initializes this target collision resistant hash. It does not require parameters.
	 */
	public void init() {
		
		isInitialized = true;
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