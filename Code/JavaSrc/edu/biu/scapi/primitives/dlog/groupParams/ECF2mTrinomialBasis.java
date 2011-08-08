package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/**
 * Elliptic curve over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manage the trinomial basis.
 * @author Moriya
 *
 */
public class ECF2mTrinomialBasis extends ECF2mGroupParams{

	private int k; 
	
	public ECF2mTrinomialBasis(int m, int k, BigInteger a, BigInteger b){
		this.m = m;
		this.k = k;
		this.a = a;
		this.b = b;
	}
	
	
	public int getK1(){
		return k;
	}
}
