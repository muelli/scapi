package edu.biu.scapi.primitives.dlog.miracl;

import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

public class MiraclDlogECF2m extends MiraclAdapterDlogEC implements DlogECF2m{

	private native long initF2mCurve(int m, int k1, int k2, int k3, byte[] a, byte[] b);
	private native long multiplyF2mPoints(long mip, long p1, long p2);
	private native long exponentiateF2mPoint(long mip, long p, byte[] exponent);
	private native long invertF2mPoint(long mip, long p);
	private native boolean validateF2mGenerator(long mip, long generator, byte[] x, byte[] y);
	private native boolean isF2mMember(long mip, long point);
	
	/**
	 * Initialize the MIRACL implementation of elliptic curve over GF[2m] 
	 * with order, generator and GroupDesc.
	 * @param groupOrder
	 * @param generator
	 * @param groupDesc
	 * @throws IllegalArgumentException
	 */
	public void init(BigInteger groupOrder, GroupElement generator,
			GroupParams groupParams) throws IllegalArgumentException{
		if (groupParams instanceof ECF2mGroupParams) {
			if (generator instanceof ECFpPointMiracl){
				//set the inner parameters
				q = groupOrder;
				this.generator = generator;
				this.groupParams = groupParams;
				
				//create MIRACL curve
				ECF2mGroupParams desc = (ECF2mGroupParams)groupParams;
				int m = desc.getM(); //get the field size
				int k1 = 0, k2 = 0, k3 = 0;
				if (desc instanceof ECF2mTrinomialBasis){
					k1 = ((ECF2mTrinomialBasis)desc).getK1();
				}
				if (desc instanceof ECF2mPentanomialBasis){
					k1 = ((ECF2mPentanomialBasis)desc).getK1();
					k2 = ((ECF2mPentanomialBasis)desc).getK2();
					k3 = ((ECF2mPentanomialBasis)desc).getK3();
				}
				if (desc instanceof ECF2mKoblitz){
					k1 = ((ECF2mPentanomialBasis)desc).getK1();
					k2 = ((ECF2mPentanomialBasis)desc).getK2();
					k3 = ((ECF2mPentanomialBasis)desc).getK3();
				}
				mip = initF2mCurve(m, k1, k2, k3, desc.getA().toByteArray(), desc.getB().toByteArray());
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
		int m = Integer.parseInt(nistEC.getProperty(name));
		int k = Integer.parseInt(nistEC.getProperty(name+"k"));
		String k2Property = nistEC.getProperty(name+"k2");
		String k3Property = nistEC.getProperty(name+"k3");
		BigInteger a = new BigInteger(nistEC.getProperty(name+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"y")));
		//set the order
		q = new BigInteger(nistEC.getProperty(name+"r"));
		
		//create the GroupParams
		ECF2mGroupParams desc = null;
		int k2=0;
		int k3=0;
		if (k2Property==null && k3Property==null){ //for trinomial basis
			desc = new ECF2mTrinomialBasis(m, k, a, b);
		} else { //pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			desc = new ECF2mPentanomialBasis(m, k, k2, k3, a, b);
		} 
		//koblitz curve
		if (name.contains("K-")){
			BigInteger h;
			if (a.equals(new BigInteger("1"))){
				h = new BigInteger("2");
			} else {
				h = new BigInteger("4");
			}
			groupParams = new ECF2mKoblitz(desc, q, h);
		} else{
			groupParams = desc;
		}
		//create MIRACL curve
		mip = initF2mCurve(m, k3, k2, k, a.toByteArray(), b.toByteArray());
				
		//create the generator
		generator = new ECF2mPointMiracl(x,y, this);	
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
		if (groupElement instanceof ECF2mPointMiracl){
			
			long p = ((ECF2mPointMiracl)groupElement).getPoint();
			//call to native inverse function
			long result = invertF2mPoint(mip, p);
			//build a ECF2mPointMiracl element from the result value
			return new ECF2mPointMiracl(result);	
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
		if ((groupElement1 instanceof ECF2mPointMiracl) && (groupElement2 instanceof ECF2mPointMiracl)){
			
			long p1 = ((ECF2mPointMiracl)groupElement1).getPoint();
			long p2 = ((ECF2mPointMiracl)groupElement2).getPoint();
			
			//call to native multiply function
			long result = multiplyF2mPoints(mip, p1, p2);
			//build a ECF2mPointMiracl element from the result value
			return new ECF2mPointMiracl(result);
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
		if (base instanceof ECF2mPointMiracl){
			
			long p = ((ECF2mPointMiracl)base).getPoint();
			//call to native exponentiate function
			long result = exponentiateF2mPoint(mip, p, exponent.toByteArray());
			//build a ECF2mPointMiracl element from the result value
			return new ECF2mPointMiracl(result);
		}
		else throw new IllegalArgumentException("groupElement doesn't match the DlogGroup");
	}
	
	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement(){
		return new ECF2mPointMiracl(this);
	}
	
	/**
	 * validate that the parameters of this curve is as expected by NIST curves
	 * @return true if the GroupParams is valid. false, otherwise
	 */
	protected  boolean validateNistParams(){
		boolean valid = true;
		//get the nist parameters
		int m = Integer.parseInt(nistEC.getProperty(nistCurveName));
		BigInteger a = new BigInteger(nistEC.getProperty(nistCurveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"b")));
	
		
		//check a, b ,m
		ECF2mGroupParams desc = (ECF2mGroupParams) groupParams;
		if (!desc.getA().equals(a) || !desc.getB().equals(b) || !(desc.getM()== m)){
			valid = false;
		}
		valid = validateBasisParams(desc);
		//koblitz curve - check n, h
		if (desc instanceof ECF2mKoblitz){
			valid = validateBasisParams(((ECF2mKoblitz) desc).getCurve());
			BigInteger n = new BigInteger(nistEC.getProperty(nistCurveName+"r"));
			if (!((ECF2mKoblitz) desc).getSubGroupOrder().equals(n)){
				valid = false;
			}
			
			if (a.equals(BigInteger.ZERO) && !((ECF2mKoblitz) desc).getCofactor().equals(new BigInteger("4"))){
				valid = false;
			}
			if (a.equals(BigInteger.ONE) && !((ECF2mKoblitz) desc).getCofactor().equals(new BigInteger("2"))){
				valid = false;
			}
		}
		return valid;
	}
	
	/**
	 * checks that the basis parameters is equal to the expected parameters
	 * @param desc - GroupParams to check
	 * @return true if valid. false otherwise
	 */
	private boolean validateBasisParams(ECF2mGroupParams desc){
		boolean valid = true;
		//get the basis parameters
		int k = Integer.parseInt(nistEC.getProperty(nistCurveName+"k"));
		int k2=0;
		int k3=0;
		
		// trinomial basis - check k
		if (desc instanceof ECF2mTrinomialBasis){ 
			if (!(((ECF2mTrinomialBasis) desc).getK1() == k)){
				valid = false;
			}
		
		} else { //pentanomial basis - check k1, k2, k3
			k2 = Integer.parseInt(nistEC.getProperty(nistCurveName+"k2"));
			k3 = Integer.parseInt(nistEC.getProperty(nistCurveName+"k3"));
			if (!(((ECF2mPentanomialBasis) desc).getK1() == k) || !(((ECF2mPentanomialBasis) desc).getK2() == k2) || !(((ECF2mPentanomialBasis) desc).getK3() == k3)){
				valid = false;
			}
			
		}
		return valid;
	}

	/**
	 * validate that the generator of this curve is as expected by NIST curves
	 * @return true if the generator is valid. false, otherwise
	 */
	protected boolean validateNistGenerator() {
		BigInteger x = new BigInteger(nistEC.getProperty(nistCurveName+"x"));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"y")));
		
		return validateF2mGenerator(mip, ((ECFpPointMiracl)generator).getPoint(), x.toByteArray(), y.toByteArray());
	}
	
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) {
		boolean member = false;
		if(element instanceof ECFpPointMiracl){
			member = isF2mMember(mip, ((ECFpPointMiracl) element).getPoint());
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
