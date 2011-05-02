/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.crypto.hash.cryptopp.
 * File: CryptoPpSHA512.java.
 * Creation date Apr 12, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.crypto.hash.cryptopp;

import edu.biu.scapi.primitives.crypto.hash.SHA512;

/**
 * @author LabTest
 *
 */
public class CryptoPpSHA512 extends CryptoPpCollResHash implements SHA512 {

	/**
	 * @param hashName
	 */
	public CryptoPpSHA512() {
		super("SHA512");
	}

	public int getHashedMsgSize() {
		
		return 64;
	}

}
