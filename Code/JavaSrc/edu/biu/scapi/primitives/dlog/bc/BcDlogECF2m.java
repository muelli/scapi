package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * 
 * @author user
 *
 */
public class BcDlogECF2m extends BcAdapterDlogEC implements DlogECF2m{

	/**
	 * Initialize the BC implementation of elliptic curve over GF[2m] 
	 * with order, generator and GroupDesc.
	 * @param groupOrder
	 * @param generator
	 * @param groupDesc
	 * @throws IllegalArgumentException
	 */
	public void init(BigInteger groupOrder, GroupElement generator,
			GroupParams groupParams) throws IllegalArgumentException{
		if (groupParams instanceof ECF2mGroupParams) {
			if (generator instanceof ECF2mPointBc){
				//set the inner parameters
				q = groupOrder;
				this.generator = generator;
				this.groupParams = groupParams;
				
				/*
				 * get the curve parameters and create the ECCurve of BC
				 */
				ECF2mGroupParams desc = (ECF2mGroupParams) groupParams;
				int m = desc.getM(); //get the field size
				int k1 = 0, k2 = 0, k3 = 0;
				BigInteger n = null, h = null;
				if (desc instanceof ECF2mTrinomialBasis){ //trinomial basis
					k1 = ((ECF2mTrinomialBasis)desc).getK1();
				}
				if (desc instanceof ECF2mPentanomialBasis){//pentanomial basis
					k1 = ((ECF2mPentanomialBasis)desc).getK1();
					k2 = ((ECF2mPentanomialBasis)desc).getK2();
					k3 = ((ECF2mPentanomialBasis)desc).getK3();
				}
				if (desc instanceof ECF2mKoblitz){ //koblitz
					k1 = ((ECF2mPentanomialBasis)desc).getK1();
					k2 = ((ECF2mPentanomialBasis)desc).getK2();
					k3 = ((ECF2mPentanomialBasis)desc).getK3();
					n = ((ECF2mKoblitz)desc).getSubGroupOrder();
					h = ((ECF2mKoblitz)desc).getCofactor();
				}
				curve = new ECCurve.F2m(m, k1, k2, k3, desc.getA(), desc.getB(), n, h);
				
			} else throw new IllegalArgumentException("generator type doesn't match the group type");
		} else throw new IllegalArgumentException("GroupDesc doesn't match the group type");
		
	}

	/**
	 * Initialize the DlogGroup with one of NIST recommended elliptic curve
	 * @param name - name of NIST curve to initialized
	 * @throws IllegalAccessException
	 */
	public void init(String name) throws IllegalArgumentException{
		
		//check the validity of the request. Meaning, the requested curve does exist. 
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
		int k2=0;
		int k3=0;
		
		//create the GroupParams
		ECF2mGroupParams desc = null;
		if (k2Property==null && k3Property==null){ //for trinomial basis
			desc = new ECF2mTrinomialBasis(m, k, a, b);
		
		} else { //pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			desc = new ECF2mPentanomialBasis(m, k, k2, k3, a, b);
		} 
		BigInteger h = null;
		//koblitz curve
		if (name.contains("K-")){
			
			if (a.equals(new BigInteger("1"))){
				h = new BigInteger("2");
			} else {
				h = new BigInteger("4");
			}
			groupParams = new ECF2mKoblitz(desc, q, h);
		} else{
			groupParams = desc;
		}
		curve = new ECCurve.F2m(m, k, k2, k3, a, b, q, h);
		
		//create the generator
		generator = new ECF2mPointBc(x,y, this);	
		nistCurveName = name; //set nist name
	}
	
	/**
	 * validate that the parameters of this curve is as expected by NIST curves
	 * @return true if the GroupParams is valid. false, otherwise
	 */
	protected  boolean validateNistParams(){
		boolean valid = true;
		//get nist parameters
		int m = Integer.parseInt(nistEC.getProperty(nistCurveName));
		BigInteger a = new BigInteger(nistEC.getProperty(nistCurveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(nistCurveName+"b")));
		
		
		//check a, b ,m
		ECF2mGroupParams desc = (ECF2mGroupParams) groupParams;
		if (!desc.getA().equals(a) || !desc.getB().equals(b) || !(desc.getM()== m)){
			valid = false;
		}
		//check that the parameters of the basis are correct
		valid = validateBasisParams(nistCurveName, desc);
		
		//koblitz curve
		if (groupParams instanceof ECF2mKoblitz){
			//check that the parameters of the underline curve are correct
			valid = validateBasisParams(nistCurveName, ((ECF2mKoblitz) desc).getCurve());
			BigInteger n = new BigInteger(nistEC.getProperty(nistCurveName+"r"));
			if (!((ECF2mKoblitz) desc).getSubGroupOrder().equals(n)){
				valid = false;
			}
			//check n,h
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
	 * Check that the basis parameters are matching the curve with th given name
	 * @param name - one of the recommended curves
	 * @param desc - GroupParams to check
	 * @return true is the parameters are valid. false, otherwise.
	 */
	private boolean validateBasisParams(String name, ECF2mGroupParams desc){
		boolean valid = true;
		//get the basis parameters
		int k = Integer.parseInt(nistEC.getProperty(name+"k"));
		int k2=0;
		int k3=0;
		
		// trinomial basis - check k
		if (desc instanceof ECF2mTrinomialBasis){ 
			if (!(((ECF2mTrinomialBasis) desc).getK1() == k)){
				valid = false;
			}
		
		} else { //pentanomial basis - check k1, k2, k3
			k2 = Integer.parseInt(nistEC.getProperty(name+"k2"));
			k3 = Integer.parseInt(nistEC.getProperty(name+"k3"));
			if (!(((ECF2mPentanomialBasis) desc).getK1() == k) || !(((ECF2mPentanomialBasis) desc).getK2() == k2) || !(((ECF2mPentanomialBasis) desc).getK3() == k3)){
				valid = false;
			}
			
		}
		return valid;
	}

	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement(){
		return new ECF2mPointBc(this);
	}
	
	/**
	 * Creates ECPoint.F2m with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECF2mPointBc(result);
	}

	
	protected boolean isOrder() {
		// TODO Auto-generated method stub
		return false;
	}

	
	protected boolean isParams() {
		// TODO Auto-generated method stub
		return false;
	}

}