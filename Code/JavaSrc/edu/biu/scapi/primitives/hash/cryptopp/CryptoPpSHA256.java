/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.cryptopp.
 * File: CryptoPpSHA256.java.
 * Creation date Apr 12, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA256;

/**
 * @author LabTest
 *
 */
public class CryptoPpSHA256 extends CryptoPpCollResHash implements SHA256 {

	/**
	 * @param hashName
	 */
	public CryptoPpSHA256() {
		super("SHA256");
	}

	public int getHashedMsgSize() {
		
		return 32;
	}

}
