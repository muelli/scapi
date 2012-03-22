package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * This class tests the performance and correctness of any implemented SHA1 algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class SHA1Test extends HashTest {

	/**
	 * Sets the given CryptographicHash object, adds data for the test vectors.
	 */
	public SHA1Test(CryptographicHash hash) {
		super(hash);
		
		//one block
		addData(toByteArray("abc"), 
				Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));
		
		addData(toByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 
				Hex.decode("84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
		
		//million a's
		addData(toByteArray(millionCharA()), 
				Hex.decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
		
		
	}

}
