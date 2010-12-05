/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;


/** 
 * @author LabTest
 */
public interface PseudorandomPermutation extends PseudorandomFunction {
	/** 
	 * @param inBytes - input bytes to invert
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff);
}