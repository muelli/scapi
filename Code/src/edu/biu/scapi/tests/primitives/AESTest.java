/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.crypto.prf.AES;

/**
 * @author LabTest
 *
 * This class tests the performance and correctness of any implemented AES algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 *
 */
public class AESTest extends PrfTest {
	
	/**
	 * 
	 */
	public AESTest(AES aes) {
		super(aes);
		

		//AES 128
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f"));//key
		
		//AES 192
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("dda97ca4864cdfe06eaf70a0ec0d7191"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617"));//key
		
		//AES 256
		addData(Hex.decode("00112233445566778899aabbccddeeff"),//input
				Hex.decode("8ea2b7ca516745bfeafc49904b496089"),//output
				Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));//key
	}
	

	/**
	 * 
	 */
	public void wrongKeyType() {
		
	}

	/**
	 * 
	 */
	public void wrongKeySize() {
		
	}

	/** 
	 * 
	 */
	public void wrongOffset() {
		
	}

	/**
	 * 
	 */
	public void wrongAlgSpec() {
		
	}

	/**
	 * 
	 */
	public void unInited() {
		
	}

	/**
	 * 
	 */
	public void wrongKeyEncoding() {
		
	}
}