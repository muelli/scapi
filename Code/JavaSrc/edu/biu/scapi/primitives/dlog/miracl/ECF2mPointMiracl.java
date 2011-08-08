package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
/**
 * This class is an adapter for F2m points of miracl
 * @author Moriya
 *
 */
public class ECF2mPointMiracl implements ECElement{

	private native long createF2mPoint(long mip, byte[] x, byte[] y, boolean[] validity);
	private native long createRandomF2mPoint(long mip, int m);
	private native void deletePointF2m(long p);
	
	private long point = 0;
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECF2mPointMiracl(BigInteger x, BigInteger y, DlogGroup curve){
		//the DlogGroup that matches this class is MiraclAdapterDlogEC
		if (curve instanceof MiraclAdapterDlogEC){
			//creates point - if the values are valid point - return true. else - return false.
			if (!createPoint(x,y,(ECF2mGroupParams)curve.getGroupParams(), ((MiraclAdapterDlogEC) curve).getMip())){
				point = 0;
				throw new IllegalArgumentException("x, y values are not a point on this curve");
			}
			//if the DlogGroup is not MiraclAdapterDlogEC throw exception
		} else throw new IllegalArgumentException("DlogGroup type doesn't match the GroupElement type");
	}
	
	/**
	 * Creates a point with the given values.
	 * @param x
	 * @param y
	 * @param mip - MIRACL pointer
	 * @return true if the point is valid. false, otherwise
	 */
	boolean createPoint(BigInteger x, BigInteger y, ECF2mGroupParams curveDesc, long mip) {
		
		boolean validity[] = new boolean[1];
		/*
		 * create the point with the given parameters,
		 * and set the point.
		 */
		point = createF2mPoint(mip, x.toByteArray(), y.toByteArray(), validity);
		System.out.println(validity[0]);
		return validity[0];
	}
	
	/**
	 *  Constructor that gets DlogGroup and choose random point in the group
	 * @param curve
	 */
	public ECF2mPointMiracl(DlogGroup curve){
		//the DlogGroup that matches this class is MiraclAdapterDlogEC
		if (curve instanceof MiraclAdapterDlogEC){
			//call for native function that creates random point in the field.
			createRandomF2mPoint(((MiraclAdapterDlogEC) curve).getMip(), 
								((ECF2mGroupParams)curve.getGroupParams()).getM());
		//if the algorithm for random element failed - throws exception
		} else throw new IllegalArgumentException("DlogGroup type doesn't match the GroupElement type");
	}
	
	/**
	 * Constructor that gets pointer to element and set it.
	 * Only our inner functions uses this constructor to set an element. 
	 * The ptr is a result of our DlogGroup functions, such as multiply.
	 * @param ptr - pointer to native point
	 */
	ECF2mPointMiracl(long ptr){
		this.point = ptr;
	}
	
	/**
	 * 
	 * @return the pointer to the point
	 */
	public long getPoint(){
		return point;
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
