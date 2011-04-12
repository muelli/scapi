/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.
 * File: UnitTests.java.
 * Creation date Apr 11, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.tests;

import edu.biu.scapi.primitives.crypto.hash.cryptopp.CryptoPpSHA1;

/**
 * @author LabTest
 *
 */
public class UnitTests {

	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {
		
		byte[] in = {1,2};
		CryptoPpSHA1 sha1 = new CryptoPpSHA1();
		
		String str = sha1.getAlgorithmName();
		
		sha1.update(in, 0, 2);
		
		System.out.println(str);

	}

}
