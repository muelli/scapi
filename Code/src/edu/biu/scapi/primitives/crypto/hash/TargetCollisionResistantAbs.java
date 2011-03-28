/**
 * 
 */
package edu.biu.scapi.primitives.crypto.hash;

import java.security.spec.AlgorithmParameterSpec;

/** 
 * <!-- begin-UML-doc -->
 * <!-- end-UML-doc -->
 * @author LabTest
 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
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