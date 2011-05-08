/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.bc.
 * File: BcSHA256.java.
 * Creation date Mar 28, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA256Digest;

import edu.biu.scapi.primitives.hash.SHA256;

/**
 * @author LabTest
 *
 */
public class BcSHA256 extends BcCollResHash implements SHA256 {

	/**
	 * 
	 */
	public BcSHA256() {

		super(new SHA256Digest());
	}
}
