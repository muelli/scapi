/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.bc.
 * File: BcSHA384.java.
 * Creation date Mar 28, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA384Digest;

import edu.biu.scapi.primitives.hash.SHA384;

/**
 * @author LabTest
 *
 */
public class BcSHA384 extends BcCollResHash implements SHA384 {

	/**
	 * 
	 */
	public BcSHA384() {

		super(new SHA384Digest());
	}
}
