/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

import javax.crypto.IllegalBlockSizeException;

/** 
 * @author LabTest
 * The class LubyRackoffPrpFromPrfVarying is one implementation that has a varying input and output length. LubyRackoffPrpFromPrfVarying is a 
 * pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length 
 * (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
 * for every input/output length.
 */
public class LubyRackoffPrpFromPrfVarying extends PrpFromPrfVarying {
	
	LubyRackoffcomputation lrComputation = new LubyRackoffcomputation();
	
	public LubyRackoffPrpFromPrfVarying(String prfVaringIOLengthName) {
		
		//get the prf using the factory and set it.
	}
	
	/** 
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException {
		
		if (inLen!=outLen){
			throw new IllegalBlockSizeException("Input and output must be of the same length");
		}
		else{
			lrComputation.computeBlock(prfVaryingIOLength, inBytes, inOff, inLen, outBytes, outOff);
		}
		
	}

	/**
	 * 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException {
		// TODO Auto-generated method stub
		
	}

	
	public String getAlgorithmName() {
		
		return "LUBY_RACKOFF_PRP_FROM_PRP_VARYING";
	}

	
	public int getBlockSize() {
		return 0;
	}


}