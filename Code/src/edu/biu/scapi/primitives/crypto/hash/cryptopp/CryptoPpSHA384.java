/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.crypto.hash.cryptopp.
 * File: CryptoPpSHA384.java.
 * Creation date Apr 12, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.crypto.hash.cryptopp;

import edu.biu.scapi.primitives.crypto.hash.SHA384;

/**
 * @author LabTest
 *
 */
public class CryptoPpSHA384 extends CryptoPpCollResHash implements SHA384 {

	/**
	 * @param hashName
	 */
	public CryptoPpSHA384() {
		super("SHA384");
	}

	public int getHashedMsgSize() {
		
		return 48;
	}

}
