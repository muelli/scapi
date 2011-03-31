/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

import javax.crypto.IllegalBlockSizeException;

/** 
 * @author LabTest
 * 
 * The class ScPrpFromPrfVarying is one implementation that has a varying input and output length. ScPrpFromPrfVarying is a 
 * pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length 
 * (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
 * for every input/output length. 
 */
public class ScPrfVaringFromPrfVaryingInput extends
		PrfVaryingFromPrfVaryingInput {
	/** 
	 * @param prfVaringInputName
	 */
	public ScPrfVaringFromPrfVaryingInput(String prfVaringInputName) {
		
	}
	

	/** 
	 * @return
	 */
	public String getAlgorithmName() {
		
		return "SC_PRF_VARY_INOUT";
	}

	/** 
	 * Not relevant - the input and the output do not have a fixed size.
	 * @return
	 */
	public int getBlockSize() {
		
		return 0;
	}


	
	/**
	 * 
	 * computetBlock
	 * Pseudocode:
	 * 
	 * outlen = outBytes.length
	 *	x = inBytes
	 *	----------------
	 *	Let m be the smallest integer for which L*m > outlen, where L is the output length of HMAC. 
	 *	FOR i = 1 to m 
	 *	compute Yi = HMAC(k,(x,outlen,i)) [key=k, data=(x,outlen,i)] 
	 *	return the first outlen bits of Y1,…,Ym  
	 * 
	 * This function is necessary since this Prf has variable input and output length.
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen){
		
		
		/*Input :
		 outlen = outBytes.length
		x = inBytes
		----------------
		Let m be the smallest integer for which L*m > outlen, where L is the output length of HMAC. 
		FOR i = 1 to m 
		compute Yi = HMAC(k,(x,outlen,i)) [key=k, data=(x,outlen,i)] 
		return the first outlen bits of Y1,…,Ym 

		*/

	}

	
}