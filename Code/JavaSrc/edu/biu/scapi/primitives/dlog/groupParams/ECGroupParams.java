package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

public abstract class ECGroupParams implements GroupParams{
	//the coefficients of the elliptic curves
	protected BigInteger a;
	protected BigInteger b;
	
	/**
	 * 
	 * @return coefficient a
	 */
	public BigInteger getA(){
		return a;
	}
	
	/**
	 * 
	 * @return coefficient b
	 */
	public BigInteger getB(){
		return b;
	}
	
	
}
