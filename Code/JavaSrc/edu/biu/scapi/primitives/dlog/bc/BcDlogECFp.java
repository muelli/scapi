package edu.biu.scapi.primitives.dlog.bc;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * 
 * @author Moriya
 *
 */
public class BcDlogECFp extends BcAdapterDlogEC implements DlogECFp{

	/**
	 * Initialize the BC implementation of elliptic curve over GF[p] 
	 * with order, generator and GroupDesc.
	 * @param groupOrder
	 * @param generator
	 * @param groupDesc
	 * @throws IllegalArgumentException
	 */
	public void init(BigInteger groupOrder, GroupElement generator,
			GroupParams groupParams) throws IllegalArgumentException{
		if (groupParams instanceof ECFpGroupParams) {
			if (generator instanceof ECFpPointBc){
				
				//set the inner parameters
				q = groupOrder;
				this.generator = generator;
				this.groupParams = groupParams;
				
				//create the ECCurve of BC
				ECFpGroupParams desc = (ECFpGroupParams) groupParams;
				curve = new ECCurve.Fp(desc.getP(), desc.getA(), desc.getB());
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
		BigInteger p = new BigInteger(nistEC.getProperty(name));
		BigInteger a = new BigInteger(nistEC.getProperty(name+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(nistEC.getProperty(name+"y")));
		
		//set the order
		q = new BigInteger(nistEC.getProperty(name+"r"));
		
		//create the GroupParams
		groupParams = new ECFpGroupParams(p, a, b);
		//create the ECCurve
		curve = new ECCurve.Fp(p, a, b);
		
		//create the generator
		generator = new ECFpPointBc(x,y, this);	
		nistCurveName = name; //set the curve name
	}
	
	/**
	 * validate that the parameters of this curve is as expected by NIST curves
	 * @return true if the GroupParams is valid. false, otherwise
	 */
	protected  boolean validateNistParams(){
		boolean valid = true;
		//get nist parameters
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
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement(){
		return new ECFpPointBc(this);
	}
	 
	/**
	 * Creates ECPoint.Fp with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECFpPointBc(result);
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
