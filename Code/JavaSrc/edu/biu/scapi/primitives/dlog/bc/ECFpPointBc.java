package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;
import java.util.Random;
import java.util.logging.Level;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement.Fp;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECGroupParams;

/**
 * This class is an adapter for ECPoint.Fp of BC
 * @author Moriya
 *
 */
public class ECFpPointBc extends ECPointBc{
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECFpPointBc(BigInteger x, BigInteger y, DlogGroup curve){
		//the DlogGroup that matches this class is BcAdapterDlogEC
		if (curve instanceof BcAdapterDlogEC){
			//checks validity
			if (!checkValidity(x, y, (ECFpGroupParams) curve.getGroupParams()))  //if not valid, throws exception
				throw new IllegalArgumentException("x, y values are not a point on this curve");
			/*
			 * create  point with the given parameters.
			 */
			point = ((BcAdapterDlogEC)curve).createPoint(x, y);
				
			//if the DlogGroup is not BcAdapterDlogEC throw exception
		} else throw new IllegalArgumentException("DlogGroup type doesn't match the GroupElement type");
	}
	
	
	/**
	 *  Constructor that gets DlogGroup and choose random point in the group
	 * @param curve
	 */
	public ECFpPointBc(DlogGroup curve){
		//the DlogGroup that matches this class is BcAdapterDlogEC
		if (curve instanceof BcAdapterDlogEC){
			ECFpGroupParams desc = (ECFpGroupParams)curve.getGroupParams();
			
			/*
			 * choosing random point on the curve
			 */
			BigInteger p = desc.getP(); //get the prime modulus
			int len = 2*(p.bitLength()); //get the security parameter for the algorithm
			Random generator = new Random();
			BigInteger x = null;
			
			/*find a point in the group*/
			for(int i=0; i<len; i++){
				x = new BigInteger(p.bitLength(), generator); //get an element
				//if the element is in the range, calculate y value corresponding to x value
				if (x.compareTo(p)<0){
					ECFieldElement.Fp xElement = new ECFieldElement.Fp(p, x);
					ECFieldElement.Fp aElement = new ECFieldElement.Fp(p, desc.getA());
					ECFieldElement.Fp bElement = new ECFieldElement.Fp(p, desc.getB());
					//compute x^3
					ECFieldElement.Fp x3 = (Fp) xElement.square().multiply(xElement);
					//compute x^3+ax+b
					ECFieldElement.Fp result = (Fp) x3.add(aElement.multiply(xElement)).add(bElement);
					//compute sqrt(x^3+ax+b)
					ECFieldElement.Fp yVal = (Fp) result.sqrt();
					if (yVal!=null){ // if there is a square root, create a point
						BigInteger y = yVal.toBigInteger();
						//create the point
						point = ((BcAdapterDlogEC)curve).createPoint(x, y);
						i=len; //stop the loop
					}
				}
			}
			//if the algorithm failed, write it to the log
			if (x.compareTo(p)>0 || point == null)
				Logging.getLogger().log(Level.WARNING, "couldn't find a random element");
			//if the DlogGroup is not BcAdapterDlogEC throw exception
		} else throw new IllegalArgumentException("DlogGroup doesn't match the GroupElement");
	}
	
	/**
	 * Constructor that gets an element and set it.
	 * Only our inner functions uses this constructor to set an element. 
	 * The ECPoint is a result of our DlogGroup functions, such as multiply.
	 * @param point
	 */
	ECFpPointBc(ECPoint point){
		this.point = point;
	}
	
	/**
	 * Checks if the x,y values are constitute a valid point in the given DlogGroup.
	 */
	boolean checkValidity(BigInteger x, BigInteger y, ECGroupParams params) {
		//the GroupParams that matches this class is ECFpGroupParams
		if (params instanceof ECFpGroupParams){
			/* construct ECFieldElements from a,b,x,y */
			ECFpGroupParams desc = (ECFpGroupParams) params;
			ECFieldElement.Fp xElement = new ECFieldElement.Fp(desc.getP(), x);
			ECFieldElement.Fp yElement = new ECFieldElement.Fp(desc.getP(), y);
			ECFieldElement.Fp aElement = new ECFieldElement.Fp(desc.getP(), desc.getA());
			ECFieldElement.Fp bElement = new ECFieldElement.Fp(desc.getP(), desc.getB());
			/*
			 * Calculates the curve equation with the given x,y.
			 */
			//compute x^3
			ECFieldElement.Fp x3 = (Fp) xElement.square().multiply(xElement);
			//compute x^3+ax+b
			ECFieldElement.Fp result = (Fp) x3.add(aElement.multiply(xElement)).add(bElement);
			//compute y^2
			ECFieldElement.Fp y2 = (Fp) yElement.square();
	
			//if the the equation is solved - the point is in the elliptic curve and return true
			if (y2.equals(result))
				return true;
			else return false;
			//if the GroupParams is not ECFpGroupParams throw exception
		} else throw new IllegalArgumentException("groupParams doesn't match the GroupElement");
	}
}
