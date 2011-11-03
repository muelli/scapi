package edu.biu.scapi.primitives.dlog.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;
import java.util.logging.Level;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.dlog.DlogECF2m;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mKoblitz;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mPentanomialBasis;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mTrinomialBasis;

/**
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moryia Farbstein)
 *
 */
public class BcDlogECF2m extends BcAdapterDlogEC implements DlogECF2m{

	/**
	 * Initialize the DlogGroup with one of NIST recommended elliptic curve
	 * @param curveName - name of NIST curve to initialized
	 * @throws IllegalAccessException
	 */
	public void init(String curveName) throws IllegalArgumentException{
		
		try {
			Properties ecProperties;
		
			ecProperties = getProperties(PROPERTIES_FILES_PATH); //get properties object containing the curve data
		
			//checks that the curveName is in the file 
			if(!ecProperties.containsKey(curveName)) { 
				throw new IllegalArgumentException("no such NIST elliptic curve"); 
			} 
			
			//check that the given curve is in the field that matches the group
			if (!curveName.startsWith("B-") && !curveName.startsWith("K-")){
				throw new IllegalArgumentException("curveName is not a curve over F2m field and doesn't match the DlogGroup type"); 
			}
			isInitialized = true; 
			doInit(ecProperties, curveName);  // set the data and initialize the curve
			
			
		} catch (IOException e) {
			Logging.getLogger().log(Level.WARNING, "error while loading the NIST elliptic curves file");
		}
	}
	
	
	/**
	 * Extracts the parameters of the curve from the properties object and initialize the groupParams, 
	 * generator and the underlying curve
	 * @param ecProperties - properties object contains the curve file data
	 * @param curveName - the curve name as it called in the file
	 * @throws UnInitializedException 
	 */
	protected void doInit(Properties ecProperties, String curveName) {
		//get the curve parameters
		int m = Integer.parseInt(ecProperties.getProperty(curveName));
		int k = Integer.parseInt(ecProperties.getProperty(curveName+"k"));
		String k2Property = ecProperties.getProperty(curveName+"k2");
		String k3Property = ecProperties.getProperty(curveName+"k3");
		BigInteger a = new BigInteger(ecProperties.getProperty(curveName+"a"));
		BigInteger b = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"b")));
		BigInteger x = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"x")));
		BigInteger y = new BigInteger(1,Hex.decode(ecProperties.getProperty(curveName+"y")));
		BigInteger q = new BigInteger(ecProperties.getProperty(curveName+"r"));
		int k2=0;
		int k3=0;
		boolean trinomial; //sign which basis the curve use
		
		if (k2Property==null && k3Property==null){ //for trinomial basis
			groupParams = new ECF2mTrinomialBasis(q, x, y, m, k, a, b);
			trinomial = true;
		
		} else { //pentanomial basis
			k2 = Integer.parseInt(k2Property);
			k3 = Integer.parseInt(k3Property);
			groupParams = new ECF2mPentanomialBasis(q, x, y, m, k, k2, k3, a, b);
			trinomial = false;
		} 
		BigInteger h = null;
		//koblitz curve
		if (curveName.contains("K-")){
			
			if (a.equals(BigInteger.ONE)){
				h = new BigInteger("2");
			} else {
				h = new BigInteger("4");
			}
			groupParams = new ECF2mKoblitz((ECF2mGroupParams) groupParams, q, h);
		}
		
		//create the curve of BC
		if (trinomial == true){
			curve = new ECCurve.F2m(m, k, a, b, q, h);
		} else {
			curve = new ECCurve.F2m(m, k, k2, k3, a, b, q, h);
		}
		
		//create the generator
		try {
			generator = new ECF2mPointBc(x,y, this);
		} catch (UnInitializedException e) {
			//creation of the generator is done after initialization of the DlogGroup so this exception shouldn't occur
		}	
	}
	
	/**
	 * @return the type of the group - ECF2m
	 */
	public String getGroupType(){
		return "elliptic curve over F2m";
	}
	
	/**
	 * Creates a random member of this Dlog group
	 * @return the random element
	 * @throws UnInitializedException 
	 */
	public GroupElement getRandomElement() throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return new ECF2mPointBc(this);
	}
	
	/**
	 * Creates a point over F2m field with the given parameters
	 * @return the created point
	 * @throws UnInitializedException 
	 */
	public ECElement getElement(BigInteger x, BigInteger y) throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return new ECF2mPointBc(x, y, this);
	}
	
	/**
	 * Creates ECPoint.F2m with the given parameters
	 */
	protected GroupElement createPoint(ECPoint result) {
		return new ECF2mPointBc(result);
	}

}