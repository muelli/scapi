/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.primitives.
 * File: SHA224Test.java.
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
 * This class tests the performance and correctness of any implemented SHA224 algorithm.
 * The test vectors are taken from http://tools.ietf.org/rfc/rfc3874.txt 
 *
 */
public class SHA224Test extends HashTest {

	public SHA224Test(TargetCollisionResistant tcr) {
		super(tcr);
		
		//one block
		addData(toByteArray("abc"), 
				Hex.decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
		
		addData(toByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 
				Hex.decode("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"));
		
		//million a's
		addData(toByteArray(millionCharA()), 
				Hex.decode("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"));
		
		
	}
	
}
