/**
 * The class LubyRackoffPrpFromPrfVarying is one implementation that has a varying input and output length. LubyRackoffPrpFromPrfVarying is a 
 * pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length 
 * (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
 * for every input/output length.
 */
package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * @author LabTest
 * 
 */
public final class LubyRackoffPrpFromPrfVarying extends PrpFromPrfVarying {
	
	LubyRackoffComputation lrComputation = new LubyRackoffComputation();
	
	public LubyRackoffPrpFromPrfVarying(String prfVaringIOLengthName) {
		
		//get the requested prpFixed from the factory. 
		prfVaryingIOLength = (PrfVaryingIOLength) PrfFactory.getInstance().getObject(prfVaringIOLengthName);
	}
	
	
	/**
	 * 
	 * @param prfFixed the underlying prf fixed. MUST be initialized.
	 */
	public LubyRackoffPrpFromPrfVarying(PrfVaryingIOLength prfVaryingIOLength){
		
		//first check that the prp fixed is initialized.
		if(prfVaryingIOLength.isInitialized()){
			//assign the prf fixed input.
			this.prfVaryingIOLength = prfVaryingIOLength;
		}
		else{//the user must pass an initialized object, otherwise throw an exception
			throw new IllegalStateException("The input variable must be initialized");
		}
		
	}
	/** 
	 * Delegate to LubyRackoffComputation object computeFuction.
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param outLen the length of the output array
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
	 * Delegate to LubyRackoffComputation object invert. The invert function inverts the permutation using the given key. Since LubyRackoff permutation can also have varying input and output length 
	 * (although the input and the output should be the same length), the common parameter <code>len<code> of the input and the output is needed.
	 * LubyRackoff has a feistel structure and thus invert is possible even though the underlying prf is not invertible.
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException {

		lrComputation.invertBlock(prfVaryingIOLength, inBytes, inOff, outBytes, outOff, len);
		
	}

	
	public String getAlgorithmName() {
		
		return "LUBY_RACKOFF_PRP_FROM_PRP_VARYING";
	}

	
	public int getBlockSize() {
		return 0;
	}


}