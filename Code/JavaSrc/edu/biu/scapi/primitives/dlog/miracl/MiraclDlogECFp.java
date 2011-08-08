package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

public class MiraclDlogECFp extends MiraclAdapterDlogEC implements DlogECFp{

	private native long initFpCurve(byte[] p, byte[] a,byte[] b);
	private native long multiplyFpPoints(long mip, long p1, long p2);
	private native long exponentiateFpPoint(long mip, long p, byte[] exponent);
	private native long invertFpPoint(long mip, long p);
	private native boolean validateFpGenerator(long mip, long generator, byte[] x, byte[] y);
	private native boolean isFpMember(long mip, long point);
	
	/**
	 * Initialize the MIRACL implementation of elliptic curve over GF[p] 
	 * with order, generator and GroupDesc.
	 * @param groupOrder
	 * @param generator
	 * @param groupDesc
	 * @throws IllegalArgumentException
	 */
	public void init(BigInteger groupOrder, GroupElement generator,
			GroupParams groupParams) throws IllegalArgumentException{
		if (groupParams instanceof ECFpGroupParams) {
			if (generator instanceof ECFpPointMiracl){
				//set the inner parameters
				q = groupOrder;
				this.generator = generator;
				this.groupParams = groupParams;
				
				//create MIRACL curve
				ECFpGroupParams curve = (ECFpGroupParams)groupParams;
				mip = initFpCurve(curve.getP().toByteArray(), curve.getA().toByteArray(), curve.getB().toByteArray());
			} else throw new IllegalArgumentException("generator type doesn't match the group type");
		} else throw new IllegalArgumentException("GroupDesc doesn't match the group type");	
	}
	
	/**
	 * Initialize the DlogGroup with one of NIST recommended elliptic curve
	 * @param name - name of NIST curve to initialized
	 * @throws IllegalAccessException
	 */
	public void init(String name) throws IllegalArgumentException{
		
		//check the validity of the request. Meaning, the requested algorithm does exist. 
		boolean valid = checkNistNameValidity(name);
		//if invalid throw IllegalArgumentException exception
		if(!valid){
			throw (new IllegalArgumentException("no such NIST elliptic curve"));
		}
		
		//get the nist parameters
		BigInteger p = new BigInteger(nistEC.getProperty(name));
		BigInteger a = new BigInteger(nistEC.getProperty(name+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"y")));
		
		//set the order
		q = new BigInteger(nistEC.getProperty(name+"r"));
		
		//create the GroupParams
		groupParams = new ECFpGroupParams(p, a, b);
		System.out.println("p is: (java)"+p);
		System.out.println("a is: (java)"+a);
		System.out.println("b is: (java)"+b);
		
		//create MIRACL curve
		mip = initFpCurve(p.toByteArray(), a.mod(p).toByteArray(), b.toByteArray());
		System.out.println(mip);
		
		//create the generator
		generator = new ECFpPointMiracl(x,y, this);	
		nistCurveName = name;
	}

	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException{
		//if the GroupElement doesn't match the DlogGroup, throw exception
		if (groupElement instanceof ECFpPointMiracl){
			
			long p = ((ECFpPointMiracl)groupElement).getPoint();
			//call to native inverse function
			long result = invertFpPoint(mip, p);
			//build a ECFpPointMiracl element from the result value
			return new ECFpPointMiracl(result);	
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, 
											  GroupElement groupElement2) 
											  throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throw exception
		if ((groupElement1 instanceof ECFpPointMiracl) && (groupElement2 instanceof ECFpPointMiracl)){
			
			long p1 = ((ECFpPointMiracl)groupElement1).getPoint();
			long p2 = ((ECFpPointMiracl)groupElement2).getPoint();
			
			//call to native multiply function
			long result = multiplyFpPoints(mip, p1, p2);
			//build a ECFpPointMiracl element from the result value
			return new ECFpPointMiracl(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) 
									 throws IllegalArgumentException{
		//if the GroupElements don't match the DlogGroup, throw exception
		if (base instanceof ECFpPointMiracl){
			
			long p = ((ECFpPointMiracl)base).getPoint();
			//call to native exponentiate function
			long result = exponentiateFpPoint(mip, p, exponent.toByteArray());
			//build a ECFpPointMiracl element from the result value
			return new ECFpPointMiracl(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement(){
		return new ECFpPointMiracl(this);
	}
	
	/**
	 * validate that the parameters of this curve is as expected by NIST curves
	 * @return true if the GroupParams is valid. false, otherwise
	 */
	protected boolean validateNistParams() {
		System.out.println("validateNistParams");
		boolean valid = true;
		//get the nist parameters
		BigInteger p = new BigInteger(nistEC.getProperty(nistCurveName));
		BigInteger a = new BigInteger(nistEC.getProperty(nistCurveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"b")));
		
		
		//check a, b ,p
		ECFpGroupParams desc = (ECFpGroupParams) groupParams;
		if (!desc.getA().equals(a) || !desc.getB().equals(b) || !(desc.getP().equals(p))){
			valid = false;
		}
		return valid;
	}

	/**
	 * validate that the generator of this curve is as expected by NIST curves
	 * @return true if the generator is valid. false, otherwise
	 */
	protected boolean validateNistGenerator() {
		System.out.println("validateNistGenerator");
		BigInteger x = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"y")));
		System.out.println(validateFpGenerator(mip, ((ECFpPointMiracl)generator).getPoint(), x.toByteArray(), y.toByteArray()));
		return validateFpGenerator(mip, ((ECFpPointMiracl)generator).getPoint(), x.toByteArray(), y.toByteArray());
	}
	
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {
		boolean member = false;
		//checks that the element is the correct object
		if(element instanceof ECFpPointMiracl){
			//call for native function that checks if the element is member in that group
			member = isFpMember(mip, ((ECFpPointMiracl) element).getPoint());
		}
		return member;
	}
	
	
	//upload MIRACL library
	static {
        System.loadLibrary("MiraclJavaInterface");
	}


	@Override
	protected boolean isOrder() {
		// TODO Auto-generated method stub
		return false;
	}
	@Override
	protected boolean isParams() {
		// TODO Auto-generated method stub
		return false;
	}
	
}
