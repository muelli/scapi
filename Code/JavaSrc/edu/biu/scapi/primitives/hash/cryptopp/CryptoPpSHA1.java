/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.crypto.hash.cryptopp.
 * File: CryptoPpSHA1.java.
 * Creation date Apr 10, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.crypto.hash.cryptopp;


import edu.biu.scapi.primitives.crypto.hash.SHA1;

/**
 * @author LabTest
 * 
 * This class is wrapper class for the crypto++ SHA1. It uses JNI in order to call the native functions of crypto++.
 *
 */
public class CryptoPpSHA1 extends CryptoPpCollResHash implements SHA1 {

	/**
	 * @param hashName
	 */
	public CryptoPpSHA1() {
		super("SHA1");
	}

	public int getHashedMsgSize() {
		
		return 20;
	}
}
