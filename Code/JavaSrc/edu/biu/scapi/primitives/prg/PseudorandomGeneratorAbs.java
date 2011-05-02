/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

/** 
 * @author LabTest
 */
public abstract class PseudorandomGeneratorAbs implements PseudorandomGenerator {
	/** 
	 */
	private KeySpec secretKeySpec;
	/** 
	 */
	private AlgorithmParameterSpec params;

	/** 
	 * @param secretKey
	 */
	public void init(KeySpec secretKey) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param secretKey
	 * @param params
	 */
	public void init(KeySpec secretKey, AlgorithmParameterSpec params) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 */
	public void getAlgorithmName() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param _byte
	 */
	public void streamSingleByte(byte bytein) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param intlen
	 * @param inOff
	 * @param inBytes
	 * @param outBytes
	 * @param outOff
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void streamBytes(byte[] in_bytes, int inOff,
			int len, int outOff, byte[] out_bytes) {
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
	public KeySpec getSecretKeySpec() {
		// begin-user-code
		// TODO Auto-generated method stub
		return null;
		// end-user-code
	}
}