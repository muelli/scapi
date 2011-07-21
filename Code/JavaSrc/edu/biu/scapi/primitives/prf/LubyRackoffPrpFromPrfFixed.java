/**
 * 
 */
package edu.biu.scapi.primitives.prf;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * @author LabTest
 */
public final class LubyRackoffPrpFromPrfFixed extends PrpFromPrfFixed {
	
	LubyRackoffComputation lrComputation = new LubyRackoffComputation();
	/**
	 * 
	 */
	public LubyRackoffPrpFromPrfFixed(String prfFixed) {

		//get the requested prpFixed from the factory. 
		this.prfFixed = (PrfFixed) PrfFactory.getInstance().getObject(prfFixed);

	}
	
	/**
	 * 
	 * @param prfFixed the underlying prf fixed. MUST be initialized.
	 */
	public LubyRackoffPrpFromPrfFixed(PrfFixed prfFixed){
		
		//first check that the prp fixed is initialized.
		if(prfFixed.isInitialized()){
			//assign the prf fixed input.
			this.prfFixed = prfFixed;
		}
		else{//the user must pass an initialized object, otherwise throw an exception
			throw new IllegalStateException("The input variable must be initialized");
		}
		
	}
	
	/**
	 * Delegate to LubyRackoffComputation object invert. The invert function inverts the permutation using the given key. Since LubyRackoff permutation can also have varying input and output length 
	 * (although the input and the output should be the same length), the common parameter <code>len<code> of the input and the output is needed.
	 * LubyRackoff has a feistel structure and thus invert is possible even though the underlying prf is not invertible.
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {

		lrComputation.invertBlock(prfFixed, inBytes, inOff, outBytes, outOff, getBlockSize());
		
	}

	
	public String getAlgorithmName() {
	
		return "LUBY_RACKOFF_PRP_FROM_PRP_FIXED";
	}

	
	public int getBlockSize() {
		
		//the input and output length are twice the size of the underlying prf
		return prfFixed.getBlockSize()*2;
	}

	/** 
	 * Delegate to LubyRackoffComputation object computeFuction.
	 * @param inBytes input bytes to compute
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute.
	 * @param outOff output offset in the outBytes array to take the result from
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {

		lrComputation.computeBlock(prfFixed, inBytes, inOff, getBlockSize(), outBytes, outOff);
		
	}

	
}