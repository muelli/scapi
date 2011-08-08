package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECGroupParams;

/**
 * This class is the adapter to Bouncy Castle implementation of elliptic curves.
 * @author Moriya
 *
 */
public abstract class BcAdapterDlogEC extends DlogGroupEC 
							 implements DlogEllipticCurve{

	protected ECCurve curve; // BC elliptic curve
	
	/**
	 * Creates a ECPoint from the given x,y
	 * @param x
	 * @param y
	 * @return ECPoint - the created point
	 */
	public ECPoint createPoint(BigInteger x, BigInteger y){
		return curve.createPoint(x, y, false);
	}
	
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		if (element instanceof ECPointBc)
		{
			ECPointBc point = (ECPointBc)element;
			//check the validity of the point
			return point.checkValidity(point.getPoint().getX().toBigInteger(), point.getPoint().getY().toBigInteger(), (ECGroupParams)groupParams);
		} else throw new IllegalArgumentException("element type doesn't match the group type");
		
	}
	
	/**
	 * Check if the given generator is indeed the generator of the group
	 * we assume that the order of the group is prime or the cofactor is 2 or 4.
	 * @return true, is the generator is valid, false otherwise.
	 */
	public boolean isGenerator(){
		return false;
	}
	
	
	
	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		//if the GroupElement doesn't match the DlogGroup, throw exception
		if (groupElement instanceof ECPointBc){
			//get the ECPoint
			ECPoint p1 = ((ECPointBc)groupElement).getPoint();
			
			/* 
			 * BC treat EC as additive group while we treat that as multiplicative group. 
			 * Therefore, invert point is negate.
			 */
			ECPoint result = p1.negate();
			
			//create GroupElement from the result
			return createPoint(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/*
	 * each of the concrete classes implements this function.
	 * BcDlogECFp creates an ECPoint.Fp
	 * BcDlogECF2m creates an ECPoint.F2m
	 */
	protected abstract GroupElement createPoint(ECPoint result);

	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) 
									 throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throw exception
		if (base instanceof ECPointBc){
			//get the ECPoint
			ECPoint p1 = ((ECPointBc)base).getPoint();
			
			/* 
			 * BC treat EC as additive group while we treat that as multiplicative group. 
			 * Therefore, exponentiate point is multiply.
			 */
			ECPoint result = p1.multiply(exponent);
			
			//create GroupElement from the result
			return createPoint(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
											  GroupElement groupElement2) 
											  throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throw exception
		if ((groupElement1 instanceof ECPointBc) && (groupElement2 instanceof ECPointBc)){
			
			//get the ECPoints
			ECPoint p1 = ((ECPointBc)groupElement1).getPoint();
			ECPoint p2 = ((ECPointBc)groupElement2).getPoint();
			
			/* 
			 * BC treat EC as additive group while we treat that as multiplicative group. 
			 * Therefore, multiply point is add.
			 */
			ECPoint result = p1.add(p2);
			
			//create GroupElement from the result
			return createPoint(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * validate that the generator of this curve is as expected by NIST curves
	 * @return true if the generator is valid. false, otherwise
	 */
	protected boolean validateNistGenerator() {
		//get the expected values
		BigInteger x = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"y")));
		
		//compare the expected values to the current values. if equal - return true
		if (((ECPointBc)generator).getPoint().getX().toBigInteger().equals(x) &&
			((ECPointBc)generator).getPoint().getY().toBigInteger().equals(y))
			return true;
		else return false; // else return false
	}
	
	
	
		
	
	
}
