package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prf.PrpVaryingIOLength;

/**
 * This class tests the performance and correctness of LubyRackoffPrpFromPrfVarying algorithm.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class LubyRackoffPrpFromPrfVaryingTest extends PrpVaringIOLengthTest {
	
	/**
	 * Sets the given AES object, adds data for the test vectors.
	 */
	public LubyRackoffPrpFromPrfVaryingTest(PrpVaryingIOLength prpVaryingIOLength) {
		super(prpVaryingIOLength);
		
		
		addDataInvertCompute(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));//key
		
		addDataInvertCompute(Hex.decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),//input
				Hex.decode("000102030405060708090a0b0c0d0e0f"));//key
	}

	/**
	 * Some wrong behavior functions need an input for the calculations. 
	 * This function overrides the super implementation because the super returns the input from the test vector "testDataVector", which is empty in this object.
	 * Thus, returns the input from the test vector "testDataInvertcompute".
	 * @return the data for wrongBehavior tests 
	 */
	protected byte[] getData() {
		return testDataInvertcompute.get(0).input;
	}
	
	/**
	 * Some wrong behavior functions need a key for the calculations. 
	 * This function overrides the super implementation because the super returns the key from the test vector "testDataVector", which is empty in this object.
	 * Thus, returns the key from the test vector "testDataInvertcompute".
	 * @return the key for wrongBehavior tests
	 */
	protected byte[] getKey() {
		return testDataInvertcompute.get(0).key;
	}
}
