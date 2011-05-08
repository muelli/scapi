/**
 * 
 */
package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

/** 
 * @author LabTest
 */
public class LubyRackoffPrpFromPrfFixed extends PrpFromPrfFixed {
	
	LubyRackoffComputation lrComputation = new LubyRackoffComputation();
	/**
	 * 
	 */
	public LubyRackoffPrpFromPrfFixed(String prpFixed) {

		

	}
	
	

	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {
		// TODO Auto-generated method stub
		
	}

	
	public String getAlgorithmName() {
	
		return "LUBY_RACKOFF_PRP_FROM_PRP_FIXED";
	}

	
	public int getBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	/** 
	 * @param inBytes- input bytes to compute
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {

		lrComputation.computeBlock(prfFixed, inBytes, inOff, getBlockSize(), outBytes, outOff);
		
	}

	
}