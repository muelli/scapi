/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.cryptopp.
 * File: CryptoPpSHA384.java.
 * Creation date Apr 12, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA384;

/**
 * @author LabTest
 *
 */
public final class CryptoPpSHA384 extends CryptoPpCollResHash implements SHA384 {

	/**
	 * @param hashName
	 */
	public CryptoPpSHA384() {
		super("SHA384");
	}

}
