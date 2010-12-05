/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

/** 
 * <!-- begin-UML-doc -->
 * <!-- end-UML-doc -->
 * @author LabTest
 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
 */
public abstract class PseudorandomPermutationAbs extends
		PseudorandomFunctionAbs implements PseudorandomPermutation {
	/** 
	 * @param inBytes - input bytes to invert
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public abstract void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff); 
}