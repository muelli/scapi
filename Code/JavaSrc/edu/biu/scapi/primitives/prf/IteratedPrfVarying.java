/**
 * 
 */
package edu.biu.scapi.primitives.prf;

import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * @author LabTest
 * 
 
 */
public class IteratedPrfVarying extends
		PrfVaryingFromPrfVaryingInput {
	/** 
	 * @param prfVaringInputName - the prf to use. 
	 * The initialization of this prf is in the function init of PrfVaryingFromPrfVaryingInput.
	 */
	public IteratedPrfVarying(String prfVaringInputName) {
		//get the requested prfVaringInput from the factory. 
		prfVaryingInputLength = (PrfVaryingInputLength) PrfFactory.getInstance().getObject(prfVaringInputName);
	}
	
	public void init(SecretKey secretKey) {

		prfVaryingInputLength.init(secretKey);
		
	}
	
	public boolean isInitialized() {

		//if the hmac is initialized than the HKDF is initialized as well.
		return prfVaryingInputLength.isInitialized(); 
	}
	

	/** 
	 * @return the algorithm name - SC_PRF_VARY_INOUT.
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
	 * 
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
	 * @param inBytes - input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, 
			byte[] outBytes, int outOff, int outLen) {
		
		int prfLength = prfVaryingInputLength.getBlockSize();            //the output size of the prfVaringInputLength
		int rounds = (int) Math.ceil((float)outLen / (float)prfLength);  //the smallest integer for which rounds*)prfLength > outlen
		byte[] intermediateOutBytes = new byte[prfLength];               //round result
		byte[] currentInBytes = new byte[inLen+2];                       //the data for the prf 
		
		Integer outLenByte = new Integer(outLen);
		
		//copy the x (inSize) to the input of the prf in the beginning
		System.arraycopy(inBytes, 0, currentInBytes, 0, inLen);
		//copy the outLen to the input of the prf after the x
		currentInBytes[inLen] = outLenByte.byteValue();
		
		Integer round;
		
		for(int i=1; i<=rounds; i++) {
			
			round = new Integer(i);
			
			//copy the i to the input of the prf
			currentInBytes[inLen+1] = round.byteValue();
			
			//operate the computeBlock of the prf to get the round output
			try {
				prfVaryingInputLength.computeBlock(currentInBytes, 0, currentInBytes.length, intermediateOutBytes, 0);
			} catch (IllegalBlockSizeException e) {
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
			
			
			if (i==rounds) { //copy the round result to the output byte array
				//in case of the last round - copy only the number of bytes left to match outLen
				System.arraycopy(intermediateOutBytes, 0, outBytes, (i - 1)*prfLength, outLen-((i-1)*prfLength));
			} else { //in other cases - copy all the result bytes
				System.arraycopy(intermediateOutBytes, 0, outBytes, (i-1)*prfLength, prfLength);
			}
		}
	}

	
}