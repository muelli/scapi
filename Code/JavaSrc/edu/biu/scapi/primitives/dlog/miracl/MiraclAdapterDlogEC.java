package edu.biu.scapi.primitives.dlog.miracl;



import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	private native long createMip();
	//protected native long createExponentiationsMap();
	
	//protected long exponentiationsMap = 0;
	protected long mip = 0; ///MIRACL pointer

	/*
	 * 
	 * @return mip - miracl pointer
	 */
	public long getMip(){
		if (mip==0)
			mip = createMip();
		return mip;
	}
	
}

