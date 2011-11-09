package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;

/**
 * This class is an adapter for Fp points of miracl
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ECFpPointMiracl implements ECElement{

	private native long createFpPoint(long mip, byte[] x, byte[] y, boolean[] validity);
	private native long createRandomFpPoint(long mip, byte[] p, boolean[] validity);
	private native void deletePointFp(long p);
	private native byte[] getXValueFpPoint(long mip, long point);
	private native byte[] getYValueFpPoint(long mip, long point);
	
	private long point = 0;
	private long mip = 0;
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECFpPointMiracl(BigInteger x, BigInteger y, MiraclDlogECFp curve){
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//call for a native function that creates an element in the field
		point = createFpPoint(mip, x.toByteArray(), y.toByteArray(), validity);
		
		//if the creation failed - throws exception
		if (validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		}	
	}
	
	/**
	 *  Constructor that gets DlogGroup and chooses a random point in the group
	 * @param curve
	 * @throws UnInitializedException 
	 */
	public ECFpPointMiracl(MiraclDlogECFp curve) throws UnInitializedException{
		mip = curve.getMip();
		
		boolean validity[] = new boolean[1];
		
		//call for native function that creates random point in the field.
		point = createRandomFpPoint(mip, 
							((ECFpGroupParams)curve.getGroupParams()).getP().toByteArray(), validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			Logging.getLogger().log(Level.WARNING, "couldn't find random element");
		}
	}
	
	/**
	 * Constructor that gets pointer to element and sets it.
	 * Only our inner functions use this constructor to set an element. 
	 * The ptr is a result of our DlogGroup functions, such as multiply.
	 * @param ptr - pointer to native point
	 */
	ECFpPointMiracl(long ptr, long mip){
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
	
	public BigInteger getX(){
		
		return new BigInteger(getXValueFpPoint(mip, point));
		
	}
	
	public BigInteger getY(){
		return new BigInteger(getYValueFpPoint(mip, point));
		
	}
	
	/**
	 * delete the related point
	 */
	protected void finalize() throws Throwable{
		
		//delete from the dll the dynamic allocation of the point.
		deletePointFp(point);
	}
	
	static {
        System.loadLibrary("MiraclJavaInterface");
 }
}
