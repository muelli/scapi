/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.bc.
 * File: BcSHA224.java.
 * Creation date Mar 28, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA224Digest;

import edu.biu.scapi.primitives.hash.SHA224;

/**
 * @author LabTest
 *
 */
public class BcSHA224 extends BcCollResHash implements SHA224 {

	/**
	 * 
	 */
	public BcSHA224() {

		super(new SHA224Digest());
	}
}
