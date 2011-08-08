package edu.biu.scapi.primitives.dlog.miracl;



import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	protected long mip = 0; ///MIRACL pointer
	
	/**
	 * 
	 * @return mip - miracl pointer
	 */
	public long getMip(){
		return mip;
	}

	/**
	 * Check if the given generator is indeed the generator of the group
	 * @return true, is the generator is valid, false otherwise.
	 */
	public boolean isGenerator(){
		return false;
	}
	
	
}

