package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

public abstract class ECGroupParams extends GroupParams{
	//the coefficients of the elliptic curves
	protected BigInteger a;
	protected BigInteger b;
	protected BigInteger xG;
	protected BigInteger yG;
	
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
	
	/**
	 * 
	 * @return the x value of the generator point
	 */
	public BigInteger getXg(){
		return xG;
	}
	
	/**
	 * 
	 * @return the y value of the generator point
	 */
	public BigInteger getYg(){
		return yG;
	}
}
