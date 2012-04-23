package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
/**
 * This class is an adapter for F2m points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECF2mPointMiracl implements ECElement{

	private native long createF2mPoint(long mip, byte[] x, byte[] y, boolean[] validity);
	private native long createF2mPointFromX(long mip, byte[] x, boolean[] validity);
	private native long createRandomF2mPoint(long mip, int m, int seed, boolean[] validity);
	private native boolean checkInfinityF2m(long point);
	private native byte[] getXValueF2mPoint(long mip, long point);
	private native byte[] getYValueF2mPoint(long mip, long point);
	private native void deletePointF2m(long p);
	
	private long point = 0;
	private long mip = 0;
	
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECF2mPointMiracl(BigInteger x, BigInteger y, MiraclDlogECF2m curve){
		
		mip = curve.getMip();
		boolean validity[] = new boolean[1];

		//creates a point in the field with the given parameters
		point = createF2mPoint(mip, x.toByteArray(), y.toByteArray(), validity);
		
		//if the creation failed - throws exception
		if (validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		}
	}
	
	/**
	 *  Constructor that gets DlogGroup and chooses a random point in the group
	 * @param curve
	 */
	public ECF2mPointMiracl(MiraclDlogECF2m curve){
	
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//generates a seed to initiate the random number generator of miracl
		int seed = new BigInteger(new SecureRandom().generateSeed(20)).intValue();
		
		//call for native function that creates random point in the field.
		point = createRandomF2mPoint(mip, ((ECF2mGroupParams)curve.getGroupParams()).getM(), seed, validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			Logging.getLogger().log(Level.WARNING, "couldn't find random element");
		}
	}
	
	/**
	 * Constructor that gets a x coordinates , calculates its corresponding y and set the point with these arguments
	 * @param x the x coordinate
	 * @param curve
	 */
	ECF2mPointMiracl(BigInteger x, MiraclDlogECF2m curve){
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//call for native function that creates random point in the field.
		point = createF2mPointFromX(mip, x.toByteArray(), validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("the given x has no corresponding y in the current curve");
		}
	}
	
	/**
	 * Constructor that gets pointer to element and sets it.
	 * Only our inner functions use this constructor to set an element. 
	 * The ptr is a result of our DlogGroup functions, such as multiply.
	 * @param ptr - pointer to native point
	 */
	ECF2mPointMiracl(long ptr, long mip){
		this.point = ptr;
		this.mip = mip;
	}
	
	
	/**
	 * 
	 * @return the pointer to the point
	 */
	long getPoint(){
		return point;
	}
	
	public boolean isInfinity(){
		return checkInfinityF2m(point);
	}
	
	public BigInteger getX(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getXValueF2mPoint(mip, point));
	}
	
	public BigInteger getY(){
		//in case of infinity, there is no coordinates and returns null
		if (isInfinity()){
			return null;
		}
		
		return new BigInteger(getYValueF2mPoint(mip, point));
	}
	
	public boolean equals(Object elementToCompare){
		if (!(elementToCompare instanceof ECF2mPointMiracl)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		ECF2mPointMiracl element = (ECF2mPointMiracl) elementToCompare;
		if ((element.getX().compareTo(getX()) ==0) && (element.getY().compareTo(getY()) == 0)){
			return true;
		}
		return false;
	}
	
	public void release(){
		//delete from the dll the dynamic allocation of the point.
		deletePointF2m(point);
	}
	
	/**
	 * delete the related point
	 */
	protected void finalize() throws Throwable{
		
		//delete from the dll the dynamic allocation of the point.
		deletePointF2m(point);
	}
	
	static {
        System.loadLibrary("MiraclJavaInterface");
	}

}
