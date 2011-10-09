package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
/**
 * This class is an adapter for F2m points of miracl
 * @author Moriya
 *
 */
public class ECF2mPointMiracl implements ECElement{

	private native long createF2mPoint(long mip, byte[] x, byte[] y, boolean[] validity);
	private native long createRandomF2mPoint(long mip, int m, boolean[] validity);
	private native void deletePointF2m(long p);
	
	private long point = 0;
	
	/**
	 * Constructor that accepts x,y values of a point. 
	 * if the values are valid - set the point.
	 * @param x
	 * @param y
	 * @param curve - DlogGroup
	 */
	public ECF2mPointMiracl(BigInteger x, BigInteger y, MiraclDlogECF2m curve){
		
		boolean validity[] = new boolean[1];

		//creates a point in the field with the given parameters
		point = createF2mPoint(curve.getMip(), x.toByteArray(), y.toByteArray(), validity);
		
		//if the creation failed - throws exception
		if (validity[0]==false){
			point = 0;
			throw new IllegalArgumentException("x, y values are not a point on this curve");
		}
	}
	
	/**
	 *  Constructor that gets DlogGroup and choose random point in the group
	 * @param curve
	 * @throws UnInitializedException 
	 */
	public ECF2mPointMiracl(MiraclDlogECF2m curve) throws UnInitializedException{
	
		boolean validity[] = new boolean[1];
		
		//call for native function that creates random point in the field.
		point = createRandomF2mPoint(((MiraclAdapterDlogEC) curve).getMip(), 
							((ECF2mGroupParams)curve.getGroupParams()).getM(), validity);
		
		//if the algorithm for random element failed - throws exception
		if(validity[0]==false){
			point = 0;
			Logging.getLogger().log(Level.WARNING, "couldn't find random element");
		}
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
