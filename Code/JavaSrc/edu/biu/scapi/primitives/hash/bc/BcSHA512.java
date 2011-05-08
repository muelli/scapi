/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.bc.
 * File: BcSHA512.java.
 * Creation date Mar 28, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA512Digest;

import edu.biu.scapi.primitives.hash.SHA512;

/**
 * @author LabTest
 *
 */
public class BcSHA512 extends BcCollResHash implements SHA512 {

	/**
	 * 
	 */
	public BcSHA512() {

		super(new SHA512Digest());
	}
}
