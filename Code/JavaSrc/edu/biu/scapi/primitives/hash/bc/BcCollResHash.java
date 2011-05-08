/**
 * 
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.Digest;
import edu.biu.scapi.primitives.hash.TargetCollisionResistantAbs;

/** 
 * @author LabTest
 * 
 * A general adapter class of hash for Bouncy Castle. 
 * This class implements all the functionality by passing requests to the adaptee interface Digest. 
 * A concrete hash function such as SHA1 represented by the class BcSHA1 only passes the SHA1Digest object in the constructor 
 * to the base class. 
 */
public abstract class BcCollResHash extends TargetCollisionResistantAbs {
	private Digest digest;
	
	 /**
	 * @param digest - the underlying digest of BC
	 */
	public BcCollResHash(Digest digest) {
	
		this.digest = digest;
	}

	
	/** 
	 * @return the algorithm name taken from BC
	 */
	public String getAlgorithmName() {
	
		//get the name from the digest of BC
		return digest.getAlgorithmName();
	}

	/**
	 * @return - the size of the hashed message as returned from BC
	 */
	public int getHashedMsgSize() {
		
		return digest.getDigestSize();
	}

	/**
	 * update : Adds the byte array to the existing msg to hash. 
	 * @param in - input byte array
	 * @param inOffset - the offset within the byte arrat
	 * @param inLen - the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen) {
		
		digest.update(in, inOffset, inLen);
	}

	/** 
	 * @param out - the output in byte arrat
	 * @param outOffset - the offset from which to take bytes from
	 */
	public void hashFinal(byte[] out, int outOffset) {
		
		digest.doFinal(out, outOffset);
	}
}