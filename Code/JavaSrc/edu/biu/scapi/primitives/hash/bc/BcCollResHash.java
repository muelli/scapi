/**
 * 
 */
package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.Digest;

import edu.biu.scapi.exceptions.UnInitializedException;
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
	 * @param digest the underlying digest of BC
	 */
	public BcCollResHash(Digest digest) {
	
		//set the underlying bc digest
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
	 * @return the size of the hashed message as returned from BC
	 */
	public int getHashedMsgSize() {
		
		//get the size from the underlying digest
		return digest.getDigestSize();
	}

	/**
	 * Adds the byte array to the existing message to hash. 
	 * @param in input byte array
	 * @param inOffset the offset within the byte array
	 * @param inLen the length. The number of bytes to take after the offset
	 * @throws UnInitializedException 
	 * */
	public void update(byte[] in, int inOffset, int inLen) throws UnInitializedException {
		//check that the object is initialized
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//check that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+inLen > in.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		//delegate the update request to the underlying digest
		digest.update(in, inOffset, inLen);
	}

	/** 
	 * Completes the hash computation and puts the result in the out array.
	 * @param out the output in byte array
	 * @param outOffset the offset from which to take bytes from
	 * @throws UnInitializedException 
	 */
	public void hashFinal(byte[] out, int outOffset) throws UnInitializedException {
		//check that the object is initialized
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//check that the offset and length are correct
		if ((outOffset > out.length) || (outOffset+getHashedMsgSize() > out.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//delegate the update request to the underlying digest by calling it's function doFinal. This function
		//will update the out array.
		digest.doFinal(out, outOffset);
	}
}