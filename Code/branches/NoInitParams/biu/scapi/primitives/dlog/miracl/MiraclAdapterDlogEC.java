package edu.biu.scapi.primitives.dlog.miracl;



import java.io.IOException;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	protected MiraclAdapterDlogEC(){}
	
	public MiraclAdapterDlogEC(String fileName, String curveName) throws IOException {
		super(fileName, curveName);
	}

	private native long createMip();

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

