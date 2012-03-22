package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.hash.CryptographicHash;

/** 
 * This class tests the performance and correctness of any implemented SHA384 algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf 
 *
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public class SHA384Test extends HashTest {

	/**
	 * Sets the given CryptographicHash object, adds data for the test vectors.
	 */
	public SHA384Test(CryptographicHash tcr) {
		super(tcr);
		
		//one block
		addData(toByteArray("abc"), 
				Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
		
		addData(toByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"), 
				Hex.decode("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"));
		
		//million a's
		addData(toByteArray(millionCharA()), 
				Hex.decode("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"));
		
		
	}
}
