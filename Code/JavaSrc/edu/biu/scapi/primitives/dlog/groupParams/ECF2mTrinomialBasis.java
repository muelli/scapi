package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/**
 * Elliptic curve over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manage the trinomial basis.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moryia Farbstein)
 *
 */
public class ECF2mTrinomialBasis extends ECF2mGroupParams{

	private int k; 
	
	public ECF2mTrinomialBasis(BigInteger q, BigInteger xG, BigInteger yG, int m, int k, BigInteger a, BigInteger b){
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.m = m;
		this.k = k;
	}
	
	
	public int getK1(){
		return k;
	}
}
