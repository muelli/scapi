/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.primitives.
 * File: SHA256Test.java.
 * Creation date Apr 5, 2011
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
 * This class tests the performance and correctness of any implemented SHA256 algorithm.
 * The test vectors are taken from http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf 
 *
 */
public class SHA256Test extends HashTest {

	public SHA256Test(TargetCollisionResistant tcr) {
		super(tcr);
		
		//one block
		addData(toByteArray("abc"), 
				Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
			
		addData(toByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 
				Hex.decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
		
		//milion a's
		addData(toByteArray(millionCharA()), 
				Hex.decode("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
		
		
	}
}
