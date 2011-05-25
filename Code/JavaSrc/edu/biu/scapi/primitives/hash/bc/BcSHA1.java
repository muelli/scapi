/**
 * 
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA1Digest;

import edu.biu.scapi.primitives.hash.SHA1;

/** 
 * @author LabTest
 */
public final class BcSHA1 extends BcCollResHash implements SHA1 {
	/** 
	 * pass the digest SHA1 of BC. 
	 */
	public BcSHA1() {
		//pass the digest SHA1 of BC. 
		super(new SHA1Digest());
	}
}