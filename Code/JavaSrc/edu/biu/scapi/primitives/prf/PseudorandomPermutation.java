/**
 * Pseudorandom permutations are bijective pseudorandom functions that are efficiently invertible. 
 * As such, they are of the pseudorandom function type and their input length always equals their output length. 
 * In addition (and unlike general pseudorandom functions), they are efficiently invertible.
 */
package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.UnInitializedException;


/** 
 * @author LabTest
 */
public interface PseudorandomPermutation extends PseudorandomFunction {
	/** 
	 * Inverts the permutation using the given key. This function is a part of the PseudorandomPermutation interface since any PseudorandomPermutation must be efficiently invertible (given the key). 
	 * For block ciphers, for example, the length is known in advance and so there is no need to specify the length.
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff) throws IllegalBlockSizeException, UnInitializedException;
	
	/** 
	 * Inverts the permutation using the given key. Since PseudorandomPermutation can also have varying input and output length 
	 * (although the input and the output should be the same length), the common parameter <code>len<code> of the input and the output is needed.
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param len the length of the input and the output
	 * @throws IllegalBlockSizeException 
	 * @throws UnInitializedException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff, int len) throws IllegalBlockSizeException, UnInitializedException;
}