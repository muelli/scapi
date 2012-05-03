package edu.biu.scapi.primitives.dlog.miracl;



import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroupEC;

public abstract class MiraclAdapterDlogEC extends DlogGroupEC 
										  implements DlogEllipticCurve{
	
	protected int window = 0;
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
	
	public void setWindow(int val){
		window = val;
	}
	
	protected int getWindow() throws UnInitializedException{
		if (window != 0){
			return window;
		}
		int bits = getOrder().bitLength();
		if (bits <= 256){
			window =  8;
		} else {
			window = 10;
		}
		return window;
	}
}

