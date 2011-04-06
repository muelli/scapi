/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.primitives.
 * File: SHA512Test.java.
 * Creation date Apr 4, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;

/**
 * @author LabTest
 *
 * This class tests the performance and correctness of any implemented SHA512 algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf 
 *
 */
public class SHA512Test extends HashTest {

	
	/**
	 * @param tcr
	 */
	public SHA512Test(TargetCollisionResistant tcr) {
		super(tcr);
		
		//one block
		addData(toByteArray("abc"), 
				Hex.decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
		
		addData(toByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"), 
				Hex.decode("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));
		
		//million a's
		addData(toByteArray(millionCharA()), 
				Hex.decode("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"));
		
		
	}
	/**
	 * 
	 */
	/*public boolean testVector() {

		return false;
		
	}*/
	/**
	 * 
	 * millionCharA - create a string that contain 1,000,000 characters of a
	 * @return
	 */
	
	/**
	 * 
	 */
	public void wrongOffset() {
		
	}
}
