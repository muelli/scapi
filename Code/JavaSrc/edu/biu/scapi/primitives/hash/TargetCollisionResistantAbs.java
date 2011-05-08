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

	/** 
	 * Initializes this target collision resistant hash with the auxiliary parameters
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params) {
		
		this.params = params;
	}

	/** 
	 * @return the parameter spec of this target collision resistant hash
	 */
	public AlgorithmParameterSpec getParams() {
		return params;
	}

}