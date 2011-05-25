/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.cryptopp.
 * File: CryptoPpSHA1.java.
 * Creation date Apr 10, 2011
 * Created by LabTest
 *
 *
 * This class is wrapper class for the crypto++ SHA1. It uses JNI in order to call the native functions of crypto++.
 */
package edu.biu.scapi.primitives.hash.cryptopp;


import edu.biu.scapi.primitives.hash.SHA1;

/**
 * @author LabTest
 * 
 * 
 */
public final class CryptoPpSHA1 extends CryptoPpCollResHash implements SHA1 {

	/**
	 * 
	 */
	public CryptoPpSHA1() {
		super("SHA1");
	}


}
