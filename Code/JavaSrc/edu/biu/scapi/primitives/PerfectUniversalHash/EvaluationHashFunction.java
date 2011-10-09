/**
 * 
 */
package edu.biu.scapi.primitives.PerfectUniversalHash;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

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
	
	public int getInputSize() {
		
		return 0;
	}

	/** 
	 * @return
	 */
	public int getOutputSize() {
		
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
	 * @throws UnInitializedException 
	 * 
	 */
	public void compute(byte[] in, int inOffset, byte[] out,
			int outOffset) throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//check that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+getInputSize()> in.length)){
			throw new ArrayIndexOutOfBoundsException("input array too short");
		}
		if ((outOffset > out.length) || (outOffset+getOutputSize() > out.length)){
			throw new ArrayIndexOutOfBoundsException("output array too short");
		}
		//call the native function compute.
		computeFunction(evalHashPtr, in, inOffset, out, outOffset);
		
	}
	
 static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	 }
}