package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prg.PseudorandomGenerator;
/**
 * This class tests the performance and correctness of any implemented RC4 pseudorandom generator.
 * The test vectors are taken from http://www.freemedialibrary.com/index.php/RC4_test_vectors
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class RC4Test extends PrgTest {
	/**
	 * Sets the given RC4 object, adds data for the test vectors.
	 */
	public RC4Test(PseudorandomGenerator prg) {
		super(prg);


		//RC4
		addData(8,//len
				Hex.decode("02dca4aa068997af"),//output
				Hex.decode("0123456789abcdef"));//key
		
		
		addData(8,//len
				Hex.decode("587f08db33955cdb"),//output
				Hex.decode("0000000000000000"));//key
		
		addData(10,//len
				Hex.decode("2b6892c86e002de856b0"),//output
				Hex.decode("ef012345"));//key
	}

}
