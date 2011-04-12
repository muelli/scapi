/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.crypto.hash.cryptopp.
 * File: CryptoPpSHA1.java.
 * Creation date Apr 10, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.crypto.hash.cryptopp;


import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.primitives.crypto.hash.SHA1;

/**
 * @author LabTest
 * 
 * This class is wrapper class for the crypto++ SHA1. It uses JNI in order to call the native functions of crypto++.
 *
 */
public class CryptoPpSHA1 implements SHA1 {

	private long sha1Ptr;
	
	//native functions. These functions are implemented in a c++ dll using JNI that we load.
	private native long createSHA1(); 
	private native String getSHA1Name(long ptr);
	private native long getDigestSize(long ptr);
	private native void SHA1Update(long ptr, byte[] input, long len);
	private native void SHA1Final(long ptr, byte[] output);
	private native void deleteSHA1(long ptr);
	/**
	 * 
	 */
	public CryptoPpSHA1() {
		
		
		//instantiate a SHA1 object in crypto++. Remember to delete it using the finalize method.
		//we keep a pointer to the created SHA1 object in c++.
		sha1Ptr = createSHA1();
		
	}
	
	/**
	 * 
	 */
	public String getAlgorithmName() {
		
		//get the algorithm name as crypto++ call it
		return getSHA1Name(sha1Ptr);
	}

	/**
	 * 
	 */
	public int getHashedMsgSize() {
		
		//no need to call the JNI. SHA1 has a fixed digest size of 20.
		return 20;
	}

	/**
	 * 
	 */
	public AlgorithmParameterSpec getParams() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * 
	 */
	public void hashFinal(byte[] out, int outOffset) {
		
		//call the native function final. There is no use of the offset in the native code and thus should be dealt before
		//the call to the native function.
		SHA1Final(sha1Ptr, out);

	}

	/**
	 * There are no params for this implementation. No need to init the object with params 
	 */
	public void init(AlgorithmParameterSpec params) {

	}

	/**
	 * 
	 */
	public void update(byte[] in, int inOffset, int inLen) {
		
			SHA1Update(sha1Ptr, in, inLen);
	}
	
	/**
	 * delete the related SHA1 object
	 */
	protected void finalize() throws Throwable {
		// TODO Auto-generated method stub
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("JavaInterface");
	    }

}
