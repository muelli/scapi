package edu.biu.scapi.primitives.trapdoor_permutation.TPElement.cryptopp;

import java.math.BigInteger;
/** 
 * @author LabTest
 */
public final class CryptoPpRabinElement extends CryptoPpTrapdoorElement{
	
	// the pointer to the Integer native element
	private native long getPointerToRandomRabinElement(byte[] modN); 
	
	/**
	 * Constructor that get the mod n and sample a number between 1 to mod n with a square root mod(N) to be the element
	 * @param modN
	 */
	public CryptoPpRabinElement(BigInteger modN) {
			pointerToInteger = getPointerToRandomRabinElement(modN.toByteArray());
		}
		
	/**
	 * Constructor that get the mod n and a value to be the element. 
	 * Because the element doesn't contains p, q we can't check if the value has a square root modN 
	 * so we can't know if the element is valid Rabin element. Therefore, we don't do any checks and save 
	 * the value as is. Any trapdoor permutation that use this element will check validity before using.
	 * @param modN - mod n
	 * @param x - the element value
	 */
	public CryptoPpRabinElement(BigInteger modN, BigInteger x) {
		pointerToInteger = getPointerToElement(x.toByteArray());
	}
	
	/**
	 * Constructor that get a pointer and set it to be the pointer. we assume that the pointer is valid
	 * @param ptr - pointer
	 */
	public CryptoPpRabinElement(long ptr) {
		
		pointerToInteger = ptr;
	}
}
