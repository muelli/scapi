package edu.biu.scapi.primitives.dlog.groupParams;


import java.math.BigInteger;
/**
 * This class holds the parameters of an Elliptic curve over Zp.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpGroupParams extends ECGroupParams{

	private BigInteger p; //modulus 
	
	/**
	 * Sets p, a, b parameters
	 * @param p
	 * @param a
	 * @param b
	 */
	public ECFpGroupParams(BigInteger q, BigInteger xG, BigInteger yG, BigInteger p, BigInteger a, BigInteger b) {
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.p = p;
	}
	
	/**
	 * 
	 * @return p
	 */
	public BigInteger getP(){
		return p;
	}
}
