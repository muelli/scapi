package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.DlogGroupAbs;
import edu.biu.scapi.primitives.dlog.DlogZp;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;

public class CryptoPpDlogZp extends DlogGroupAbs implements DlogZp{

	private long PointerToGroup = 0; //pointer to the native group object
	
	/* native functions for the Dlog functionality*/
	private native long createDlogZp(byte[] p, long element);
	private native long inverseElement(long group, long element);
	private native long exponentiateElement(long group, long element, byte[] exponent);
	private native long multiplyElements(long group, long element1, long element2);
	private native void deleteDlogZp(long group);
	
	/**
	 * 
	 * Initialize the CryptoPP implementation of Dlog over Zp* 
	 * with order, generator and GroupDesc.
	 * @param groupOrder
	 * @param generator
	 * @param groupDesc
	 * @throws IllegalArgumentException
	 */
	public void init(BigInteger groupOrder, GroupElement generator,
			GroupParams groupParams) throws IllegalArgumentException{
		if (groupParams instanceof ZpGroupParams) {
			if (generator instanceof ZpElementCryptoPp){
				//set the inner parameters
				q = groupOrder;
				this.generator = generator;
				this.groupParams = groupParams;
				//create CryptoPP Dlog group
				PointerToGroup = createDlogZp(((ZpGroupParams) groupParams).getP().toByteArray(), ((ZpElementCryptoPp) generator).getPointerToElement());
			} else throw new IllegalArgumentException("generator type doesn't match the group type");
		} else throw new IllegalArgumentException("GroupDesc doesn't match the group type");
		
	}
	
	/**
	 * This init function is not for CryptoPpDlogZp, but for elliptic curves.
	 * @throws IllegalArgumentException
	 */
	public void init(String nistName) throws IllegalAccessException{
		throw new IllegalAccessException("this init function is not for Zp*");
	}
			
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {
		//check if element is ZpElementCryptoPp
		if (element instanceof ZpElementCryptoPp){
			BigInteger x = ((ZpElementCryptoPp) element).getElement();
			BigInteger p = ((ZpGroupParams) groupParams).getP();
			//check if the element is in the appropriate range
			if ((x.compareTo(BigInteger.ZERO)>0) && (x.compareTo(p.add(BigInteger.ONE.negate()))<=0))
				return true;
		}
		return false;
	}

	/**
	 * Check if the given generator is indeed the generator of the group
	 * Algorithm:
	 * 		If the element is the identity - return false
	 * 		Calculate element^q
	 * 			If the result is equal to 1 return false
	 * 		return true.
	 * @return true, is the generator is valid, false otherwise.
	 */
	public boolean isGenerator() {
		//check that that the generator is not the identity
		if (((ZpElementCryptoPp)generator).getElement().equals(BigInteger.ONE)== false){
			//check that generator^q is not equal to 1, -1;
			ZpElementCryptoPp result = (ZpElementCryptoPp) exponentiate(q, generator);
			BigInteger resultVal = result.getElement();
			//if the result is different from 1 or -1 return true
			if (!resultVal.equals(BigInteger.ONE)){
				return true; 
			}
		}
		return false;
	}

	/**
	 * Check if the order, generator end groupDesc are valid or not.
	 * @return true if valid, false otherwise.
	 */
	public boolean validateGroup() {
		if (isPrimeOrder()){ //check that the order is prime number
			BigInteger p = q.multiply(new BigInteger("2")).add(BigInteger.ONE);
			if (p.equals(((ZpGroupParams)groupParams).getP())){ // check that p=2q+1
				if (isGenerator()){ //check that the generator is order p
					return true;
				}
			}			
		}
		//if one of the above conditions doesn't occur - return false
		return false;
	}

	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		if (groupElement instanceof ZpElementCryptoPp){
			//call to native inverse function
			long invertVal = inverseElement(PointerToGroup, ((ZpElementCryptoPp) groupElement).getPointerToElement());
			//build a ZpElementCryptoPp element from the result value
			ZpElementCryptoPp inverseElement = new ZpElementCryptoPp(invertVal);
			return inverseElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) throws IllegalArgumentException{
		if (base instanceof ZpElementCryptoPp){
			//call to native exponentiate function
			long exponentiateVal = exponentiateElement(PointerToGroup, ((ZpElementCryptoPp) base).getPointerToElement(), exponent.toByteArray());
			//build a ZpElementCryptoPp element from the result value
			ZpElementCryptoPp exponentiateElement = new ZpElementCryptoPp(exponentiateVal);
			return exponentiateElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1,
			GroupElement groupElement2) throws IllegalArgumentException{
		
		if ((groupElement1 instanceof ZpElementCryptoPp) && (groupElement2 instanceof ZpElementCryptoPp)){
			//call to native multiply function
			long mulVal = multiplyElements(PointerToGroup, ((ZpElementCryptoPp) groupElement1).getPointerToElement(), 
										  ((ZpElementCryptoPp) groupElement2).getPointerToElement());
			//build a ZpElementCryptoPp element from the result value
			ZpElementCryptoPp mulElement = new ZpElementCryptoPp(mulVal);
			return mulElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement() {
		return new ZpElementCryptoPp(this);
	}
	
	/**
	 * delete the related Dlog group object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the Integer.
		deleteDlogZp(PointerToGroup);
		
		super.finalize();
	}
	
	//upload CryptoPP library
	 static {
	        System.loadLibrary("JavaInterface");
	 }

}
