package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;
import java.util.Random;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;

public class ZpElementCryptoPp implements ZpElement{

	private long pointerToElement;
	
	private native long getPointerToElement(byte[] element);
	private native long deleteElement(long element);
	private native byte[] getElement(long element);
		
	/**
	 * This constructor accepts x value and DlogGroup.
	 * If x is valid, sets it. else, throws exception 
	 * @param x
	 * @param zp
	 * @throws IllegalArgumentException
	 */
	public ZpElementCryptoPp(BigInteger x, DlogGroup zp) throws IllegalArgumentException{
		//if the groupDesc doesn't match the GroupElement throw exception
		if (zp instanceof CryptoPpDlogZp){
			
			BigInteger p = ((ZpGroupParams)zp.getGroupParams()).getP(); //get the prime modulus
			
			//if the element is in the expected range, set it. else, throw exception
			if ((x.compareTo(BigInteger.ZERO)>0) && (x.compareTo(p.add(BigInteger.ONE.negate()))<=0))
				pointerToElement = getPointerToElement(x.toByteArray());
			else throw new IllegalArgumentException("element out of range");
		}
		else throw new IllegalArgumentException("DlogGroup doesn't match the GroupElement");
	}
	
	/**
	 * Constructor that gets DlogGroup and choose random element in the range [0, ..., p-1].
	 * The algorithm is: 
	 * input: modulus p of length len.
     *  BigInteger x;
     *  For i = 1 to 2*len:
	 *  x <- {0, 1}len
	 *  if x<p return x
     *  Return “fail"
     *  
	 * @param zp - dklogGroup
	 * @throws IllegalArgumentException
	 */
	public ZpElementCryptoPp(DlogGroup zp)throws IllegalArgumentException{
		//if the groupDesc doesn't match the GroupElement throw exception
		if (zp instanceof CryptoPpDlogZp){
			
			BigInteger p = ((ZpGroupParams)zp.getGroupParams()).getP(); //get the prime modulus
			int len = 2*(p.bitLength()); //get the security parameter for the algorithm
			Random generator = new Random();
			BigInteger x = null;
			
			//find an element in the range [0, ..., p-1]
			for(int i=0; i<len; i++){
				x = new BigInteger(len, generator); //get an element
				//if the element is in the range, set it. 
				if (x.compareTo(p)<0){
					pointerToElement = getPointerToElement(x.toByteArray());
					i = len;
				}
			}
			//if the algorithm failed, write it to the log
			if (x.compareTo(p)>0)
				Logging.getLogger().log(Level.WARNING, "couldn't find a random element");
		} else throw new IllegalArgumentException("GroupDesc doesn't match the GroupElement");
	}
	
	/**
	 * Constructor that gets pointer to element and set it.
	 * Only our inner functions uses this constructor to set an element. 
	 * The long value is a pointer which excepted by our native functions.
	 * @param ptr
	 */
	ZpElementCryptoPp(long ptr){
		pointerToElement = ptr;
	}
	
	/**
	 * return the pointer to the element
	 * @return
	 */
	public long getPointerToElement(){
		return pointerToElement;
	}
	
	/**
	 * @return BigInteger - value of the element
	 */
	public BigInteger getElement(){
		return new BigInteger(getElement(pointerToElement));
	}
	
	/**
	 * delete the related Dlog element object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the Integer.
		deleteElement(pointerToElement);
		
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("JavaInterface");
	 }
}
