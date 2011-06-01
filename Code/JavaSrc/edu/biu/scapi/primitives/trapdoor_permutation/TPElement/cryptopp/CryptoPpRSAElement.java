package edu.biu.scapi.primitives.trapdoor_permutation.TPElement.cryptopp;

import java.math.BigInteger;

/** 
 * @author LabTest
 */
public final class CryptoPpRSAElement extends CryptoPpTrapdoorElement{
	 
	private native long getPointerToRandomRSAElement(byte[] modN);
	
	/**
	 * Constructor that get the mod n and sample a number between 1 to (mod n -1) to be the element
	 * @param modN
	 */
	public CryptoPpRSAElement(BigInteger modN) {
		//call for native function that sample a random number and return its pointer,
		//set it to be the element pointer
		pointerToInteger = getPointerToRandomRSAElement (modN.toByteArray());
	}
		
	/**
	 * Constructor that get the mod n and a value, and if the value is valid RSA element - set it to be the element
	 * @param modN - mod n
	 * @param x - the element value
	 * @throws IllegalArgumentException
	 */
	public CryptoPpRSAElement(BigInteger modN, BigInteger x) throws IllegalArgumentException{
		
		/*check if the value is valid (between 1 to (modN) - 1 ).
		  if valid - call for native function that return pointer and set it to be the element pointer
		  if not valid - throw exception */
		if(((x.compareTo(BigInteger.ZERO))>0) && (x.compareTo(modN)<0)) {
				pointerToInteger = getPointerToElement(x.toByteArray());
		} else {
			throw new IllegalArgumentException("element out of range");
		}
	}
	
	public CryptoPpRSAElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
