package edu.biu.scapi.primitives.dlog.groupParams;


import java.math.BigInteger;

public class ECFpGroupParams extends ECGroupParams{

	private BigInteger p; //modulus 
	
	/**
	 * Sets p, a, b parameters
	 * @param p
	 * @param a
	 * @param b
	 */
	public ECFpGroupParams(BigInteger p, BigInteger a, BigInteger b) {
		this.p = p;
		this.a = a;
		this.b = b;	
	}
	
	/**
	 * 
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
}
