/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.cryptopp.
 * File: CryptoPpSHA224.java.
 * Creation date Apr 12, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA224;

/**
 * @author LabTest
 *
 */
public class CryptoPpSHA224 extends CryptoPpCollResHash implements SHA224 {

	
	/**
	 * @param hashName
	 */
	public CryptoPpSHA224() {
		super("SHA224");
	}

	public int getHashedMsgSize() {
		
		return 28;
	}

}
