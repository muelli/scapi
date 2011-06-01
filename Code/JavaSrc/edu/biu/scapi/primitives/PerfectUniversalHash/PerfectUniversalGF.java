/**
 * 
 */
package edu.biu.scapi.primitives.PerfectUniversalHash;

/** 
* @author LabTest
 */
public final class PerfectUniversalGF extends PerfectUniversalAbs {
	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName() {
		
		return "PERFECT_UNIVERSAL_GF";
	}

	/** 
	 * @return the input size of this hash function
	 */
	public int geInputSize() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	/** 
	 * @return the output size of this hash function
	 */
	public int geOutputSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	/** 
	 * Compute the hash function on the in byte array and put the result in the output byte array
	 * @param in - input byte array
	 * @param inOffset - the offset within the input byte array
	 * @param inLen - length. The number of bytes to take after the offset
	 * @param out - output byte array
	 * @param outOffset - the offset within the output byte array
	 */
	public void compute(byte[] in, int inOffset, byte[] out, int outOffset) {
		
	}

}