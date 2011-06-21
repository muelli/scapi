/**
 * 
 */
package edu.biu.scapi.primitives.PerfectUniversalHash;

import javax.crypto.SecretKey;

/** 
* @author LabTest
 */
public final class EvaluationHashFunction extends PerfectUniversalAbs {
	
	protected long evalHashPtr;
	
	private native long initHash(byte[] key, long keyOffset);
	private native void computeFunction(long evalHashPtr, byte[] in, int inOffset, byte[] out, int outOffset);
	
	
	public void init(SecretKey secretKey) {

		super.init(secretKey);
		
		//pass the key to the native function
		evalHashPtr = initHash(secretKey.getEncoded(), 0);
		
		
	}
	
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
		
		//64 bits long
		return 8;
	}

	/**
	 * 
	 */
	public String getAlgorithmName() {
		
		return "Evaluation Hash Function";
		
	}

	/**
	 * 
	 */
	public void compute(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		
		//call the native function compute.
		computeFunction(evalHashPtr, in, inOffset, out, outOffset);
		
	}
	
 static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	 }
}