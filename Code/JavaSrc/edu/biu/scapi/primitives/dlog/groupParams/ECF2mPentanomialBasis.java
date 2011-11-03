package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/**
 * Elliptic curve over F2m can be constructed with two basis types, trinomial type or pentanomial type.
 * This class manage the pentanomial basis.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moryia Farbstein)
 *
 */
public class ECF2mPentanomialBasis extends ECF2mGroupParams{

	private int k1;
	private int k2;
	private int k3;
	
	
	
	public ECF2mPentanomialBasis(BigInteger q, BigInteger xG, BigInteger yG, int m, int k1, int k2, int k3, BigInteger a, BigInteger b){
		this.q = q;
		this.xG = xG;
		this.yG = yG;
		this.a = a;
		this.b = b;
		this.m = m;
		this.k1 = k1;
		this.k2 = k2;
		this.k3 = k3;
	}
	
	public int getK1(){
		return k1;
	}
	
	public int getK2(){
		return k2;
	}
	
	public int getK3(){
		return k3;
	}

	

	
}
