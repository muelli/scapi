/**
 * Pseudorandom permutations are bijective pseudorandom functions that are efficiently invertible. 
 * As such, they are of the pseudorandom function type and their input length always equals their output length. 
 * In addition (and unlike general pseudorandom functions), they are efficiently invertible.
 */
package edu.biu.scapi.primitives.crypto.prf;

import javax.crypto.IllegalBlockSizeException;


/** 
 * @author LabTest
 */
public interface PseudorandomPermutation extends PseudorandomFunction {
	/** 
	 * @param inBytes - input bytes to invert
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException;
	
	/** 
	 * @param inBytes - input bytes to invert
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of invert.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param len - the length of the input and the output.
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff, int len) throws IllegalBlockSizeException;
}