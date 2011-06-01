package edu.biu.scapi.primitives.trapdoor_permutation.TPElement;

import java.math.BigInteger;
import java.util.Random;


public final class RSAElement implements TPElement{

	private BigInteger element; // the element value
	
	/**
	 * Constructor that get the mod n and sample a number between 1 to mod n to be the element
	 * @param modN
	 */
	public RSAElement(BigInteger modN) {
		Random generator = new Random();
		
		BigInteger randNumber = null;
		do {
			//sample a random BigInteger with modN.bitLength()+1 bits
			randNumber = new BigInteger(modN.bitLength()+1, generator);
			//drop the element if it bigger then mod(N)-2
		} while(randNumber.compareTo(modN.add(new BigInteger("-2")))>0);
		//get random BigInteger between 1 to modN-1
		randNumber = randNumber.add(new BigInteger("1"));
		
		//set it to be the element
		element = randNumber;
	}
	
	/**
	 * Constructor that get the mod n and a value, and if the value is valid RSA element- set it to be the element
	 * @param modN - mod n
	 * @param x - the element value
	 * @throws IllegalArgumentException
	 */
	public RSAElement(BigInteger modN, BigInteger x) throws IllegalArgumentException{
		
		/*check if the value is valid (between 1 to (mod n) - 1).
		  if valid - set it to be the element
		  if not valid - throw exception */
		if(((x.compareTo(BigInteger.ZERO))>0) && (x.compareTo(modN)<0)) {
			element = x;
		} else {
			throw new IllegalArgumentException("element out of range");
		}
			
	}
	
	/**
	 * @return the element
	 */
	public BigInteger getElement() {
		return element;
	}

	
}
