package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;

/**
 * Koblitz curve consists of an underlying curve and additional parameters - h,n
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moryia Farbstein)
 *
 */
public class ECF2mKoblitz extends ECF2mGroupParams{
	
	private BigInteger n; 	//order of the main subgroup
	private BigInteger h; 	//cofactor
	ECF2mGroupParams curve; //underline curve
	
	
	public ECF2mKoblitz(ECF2mGroupParams curve, BigInteger n, BigInteger h){
		this.curve = curve;
		this.n = n;
		this.h = h;
	}
	
	public int getM(){
		return curve.getM();
	}
	
	/**
	 * @return k1 of the underlying curve
	 */
	public int getK1(){
		int k1 = 0;
		if (curve instanceof ECF2mTrinomialBasis)
			k1 = ((ECF2mTrinomialBasis)curve).getK1();
		
		if (curve instanceof ECF2mPentanomialBasis)
			k1 = ((ECF2mPentanomialBasis)curve).getK1();
		
		return k1;
	}
	
	/**
	 * @return k2 of the underlying curve
	 */
	public int getK2(){
		int k2 = 0;
		if (curve instanceof ECF2mTrinomialBasis) //trinomial basis has no k2
			k2 = 0;
		
		if (curve instanceof ECF2mPentanomialBasis)
			k2 = ((ECF2mPentanomialBasis)curve).getK2();
		
		return k2;
	}
	
	/**
	 * @return k3 of the underlying curve
	 */
	public int getK3(){
		int k3 = 0;
		if (curve instanceof ECF2mTrinomialBasis) //trinomial basis has no k2
			k3 = 0;
		
		if (curve instanceof ECF2mPentanomialBasis)
			k3 = ((ECF2mPentanomialBasis)curve).getK3();
		
		return k3;
	}
	
	public BigInteger getQ(){
		return curve.getQ();
	}
	
	public BigInteger getXg(){
		return curve.getXg();
	}
	public BigInteger getYg(){
		return curve.getYg();
	}
	
	public BigInteger getA(){
		return curve.getA();
	}
	
	public BigInteger getB(){
		return curve.getB();
	}
	
	public BigInteger getSubGroupOrder(){
		return n;
	}
	
	public BigInteger getCofactor(){
		return h;
	}
	
	public ECF2mGroupParams getCurve(){
		return curve;
	}
}
