package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

public class ZpGroupParams extends GroupParams{

	private BigInteger p; //modulus
	private BigInteger xG; //generator value
	
	/**
	 * constructor that checks if the given modulus is valid (e.g. if p=2q+1 and q,p are primes).
	 * @param p
	 * @throws IllegalArgumentException
	 */
	public ZpGroupParams(BigInteger q, BigInteger xG, BigInteger p) throws IllegalArgumentException{
		this.q = q;
		
		this.xG = xG;
		
		/* check if p is valid argument */
		if (p.isProbablePrime(8)){//if p is a prime number
			//calculate q
			BigInteger r = p.subtract(BigInteger.ONE).divide(new BigInteger("2"));
			if (r.isProbablePrime(8)) //if q is a prime number
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
	
	public BigInteger getXg(){
		return xG;
	}
}
