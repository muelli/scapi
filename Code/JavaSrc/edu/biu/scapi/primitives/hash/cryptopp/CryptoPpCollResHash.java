/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.hash.cryptopp.
 * File: CryptoPpCollResHash.java.
 * Creation date Apr 12, 2011
 * Created by LabTest
 *
 *
 * 
 * A general adapter class of hash for Crypto++. 
 * This class implements all the functionality by passing requests to the adaptee c++ abstract class HashTransformation of crypto++ using the JNI dll. 
 * A concrete hash function such as SHA1 represented by the class CryptoPpSHA1 only passes the name of the hash in the constructor 
 * to this base class. 
 * Since the underlying library is written in a native language we use the JNI architecture.
 *
 */
package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.hash.TargetCollisionResistantAbs;

/**
 * @author LabTest
 * 
 */
public abstract class CryptoPpCollResHash extends TargetCollisionResistantAbs {

	protected long collHashPtr;
	
	//native functions. These functions are implemented in a c++ dll using JNI that we load. For secure coding always
	//declare native functions as private and wrap them by a java function.
	
	private native long createHash(String hashName);//creates a hash and returns the pointer. This pointer will be passed to all
													//the other functions so the created hash object will be used. This is due to
													//the lack of OOD of JNI and thus the created pointer must be passed each time.
	
	private native String algName(long ptr);//returns crypto++ name of the hash
	private native void updateHash(long ptr, byte[] input, long len); //updates the hash
	private native void finalHash(long ptr, byte[] output);//finishes the hash computation
	private native int getDigestSize(long ptr);
	private native void deleteHash(long ptr);//deletes the created pointer.
	
	
	/**
	 * Constructs the related pointer of the underlying crypto++ hash.
	 * @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know
	 * 					 which hash to create.
	 */
	public CryptoPpCollResHash(String hashName) {
		
		
		//instantiate a hash object in crypto++. Remember to delete it using the finalize method.
		//we keep a pointer to the created hash object in c++.
		collHashPtr = createHash(hashName);
		
	}
	
	/**
	 * The algorithm name taken from Crypto++
	 */
	public String getAlgorithmName() {
		
		//get the algorithm name as crypto++ call it
		return algName(collHashPtr);
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
			throw new ArrayIndexOutOfBoundsException("input array too short");
		}
		//call the native function
		updateHash(collHashPtr, in, inLen);
	}

	/** 
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
			throw new ArrayIndexOutOfBoundsException("output array too short");
		}
		//call the native function final. There is no use of the offset in the native code and thus should be dealt before
		//the call to the native function.
		finalHash(collHashPtr, out);

	}

	/** 
	 * @return the size of the hashed massage from crypto++
	 */
	public int getHashedMsgSize() {
		
		//call the native function
		return getDigestSize(collHashPtr);
	}
	
	
	/**
	 * Deletes the related collision resistant hash object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the hash.
		deleteHash(collHashPtr);
		
		super.finalize();
	}
	
	 static {
		 
		 //load the crypto++ jni dll
		 System.loadLibrary("JavaInterface");
	 }

}
