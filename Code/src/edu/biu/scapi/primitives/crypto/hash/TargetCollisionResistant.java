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
public interface TargetCollisionResistant {
	
	
	/** 
	 * Initializes this target collision resistant hash with the auxiliary parameters
	 * @param params
	 */
	public void init(AlgorithmParameterSpec params);

	/** 
	 * @return the parameter spec of this target collision resistant hash
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return The algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * @return the size of the hashed massage
	 */
	public int getHashedMsgSize();

	/**
	 * update : Adds the byte array to the existing msg to hash. 
	 * @param in - input byte array
	 * @param inOffset - the offset within the byte arrat
	 * @param inLen - the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen);

	/** 
	 * @param out - the output in byte arrat
	 * @param outOffset - the offset from which to take bytes from
	 */
	public void hashFinal(byte[] out, int outOffset);
}