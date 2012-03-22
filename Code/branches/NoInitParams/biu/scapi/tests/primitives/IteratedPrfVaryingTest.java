package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prf.PrfVaryingIOLength;

/**
 * This class tests the performance and correctness of IteratedPrfVarying algorithm.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class IteratedPrfVaryingTest extends PrfVaringIOLengthTest {

	/**
	 * Sets the given PrfVaryingIOLength object, adds data for the test vector.
	 */
	public IteratedPrfVaryingTest(PrfVaryingIOLength prfVaryingIOLength) {
		super(prfVaryingIOLength);
		
		//since there is no known vector test we have come up with a vector test that follows the pseudocode (the specific iterations were calculated
		//using the HmacTest of sha224 which is also the assumed underlying hash of the underlying prfVaryingInput.
		byte[] input = {0, 0, 0, 0, 0, 0, 0, 0};
		byte[] output = {-70, -84, -105, -88, -98, -28, -35, -49, 36, 44, 110, 37, 115, -98, 102, 123, 68, 102, -10, 60, 69, 31, 115, 106, 110, 84, 101, 54, 120, -115, -42, 41, 5, 74, 125, 110, -70, 29, 40, -89, 23, -42, -33, 126, 86, 75, -45, 8, 8, 125, 9, 7, -7, -116, -70, 17, 65, 51, 37, -63};
		
		
		addData(input ,//input
				output,//output
				Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
	
		
		
	}
	
	

}
