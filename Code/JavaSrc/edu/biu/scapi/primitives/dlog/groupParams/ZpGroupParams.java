package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

public class ZpGroupParams implements GroupParams{

	private BigInteger p; //modulus
	
	/**
	 * constructor that checks if the given modulus is valid (e.g. if p=2q+1 and q,p are primes).
	 * @param p
	 * @throws IllegalArgumentException
	 */
	public ZpGroupParams(BigInteger p)throws IllegalArgumentException{
		if (p.isProbablePrime(8)){//if p is a prime number
			//calculate q
			BigInteger q = p.subtract(BigInteger.ONE).divide(new BigInteger("2"));
			if (q.isProbablePrime(8)) //if q is a prime number
				this.p = p; //set p
			//if p or q are not primes, throw exception
			else throw new IllegalArgumentException("q = (p-1)/2 must be prime");
		} else throw new IllegalArgumentException("p must be prime");
	}
	
	/**
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
}
