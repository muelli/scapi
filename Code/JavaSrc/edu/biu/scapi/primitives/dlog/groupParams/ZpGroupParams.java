package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;
/**
 * This class holds the parameters of a Dlog group over Zp*.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
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
		
		this.p = p;
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
