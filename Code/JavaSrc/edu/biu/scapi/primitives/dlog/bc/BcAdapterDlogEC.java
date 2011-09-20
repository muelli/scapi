package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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
	 * Checks if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException{
		if (element instanceof ECPointBc)
		{
			ECPointBc point = (ECPointBc)element;
			//checks the validity of the point
			return point.checkValidity(point.getPoint().getX().toBigInteger(), point.getPoint().getY().toBigInteger(), (ECGroupParams)groupParams);
		} else throw new IllegalArgumentException("element type doesn't match the group type");
		
	}
	
	/**
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		//if the GroupElement doesn't match the DlogGroup, throws exception
		if (groupElement instanceof ECPointBc){
			//gets the ECPoint
			ECPoint point1 = ((ECPointBc)groupElement).getPoint();
			
			/* 
			 * BC treats EC as additive group while we treat that as multiplicative group. 
			 * Therefore, invert point is negate.
			 */
			ECPoint result = point1.negate();
			
			//creates GroupElement from the result
			return createPoint(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}

	/**
	 * Calculates the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) 
									 throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throws exception
		if (base instanceof ECPointBc){
			//gets the ECPoint
			ECPoint point = ((ECPointBc)base).getPoint();
			
			/* 
			 * BC treats EC as additive group while we treat that as multiplicative group. 
			 * Therefore, exponentiate point is multiply.
			 */
			ECPoint result = point.multiply(exponent);
			
			//creates GroupElement from the result
			return createPoint(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
											  GroupElement groupElement2) 
											  throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throws exception
		if ((groupElement1 instanceof ECPointBc) && (groupElement2 instanceof ECPointBc)){
			
			//gets the ECPoints
			ECPoint point1 = ((ECPointBc)groupElement1).getPoint();
			ECPoint point2 = ((ECPointBc)groupElement2).getPoint();
			
			/* 
			 * BC treats EC as additive group while we treat that as multiplicative group. 
			 * Therefore, multiply point is add.
			 */
			ECPoint result = point1.add(point2);
			
			//creates GroupElement from the result
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

}
