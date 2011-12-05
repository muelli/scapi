package edu.biu.scapi.primitives.trapdoorPermutation.TPElement.cryptopp;

import java.math.BigInteger;

import edu.biu.scapi.primitives.trapdoorPermutation.TPElement.TPElement;

/** 
 * @author LabTest
 */
public abstract class CryptoPpTrapdoorElement implements TPElement{
	/* pointer to the CryptoPP::Integer.
	 * we save the pointer to an CryptoPP::Integer object to avoid unnecessary conversions 
	 * back and force when computing and inverting.
	 */
	protected long pointerToInteger; 
	
	protected native long getPointerToElement(byte[] element);
	protected native byte[] getElement(long ptr);
	private native void deleteElement(long ptr);
	
	/**
	 * @return the pointer to the Integer
	 */
	public long getPointerToElement() {
		return pointerToInteger;
	}
	
	/**
	 * @return the BigInteger value of the Integer
	 */
	public BigInteger getElement() {
		return new BigInteger(getElement(pointerToInteger));
	}
	
	/**
	 * delete the related trapdoor permutation object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToInteger);
		
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }
}
