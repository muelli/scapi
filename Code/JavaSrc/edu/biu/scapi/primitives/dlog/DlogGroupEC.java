package edu.biu.scapi.primitives.dlog;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Properties;

/**
 * this class manages the creation of NIST recommended elliptic curves.
 * We have a properties file which contains the parameters for the curves. 
 * This class upload the file once, and construct a properties object from it.
 * @author Moriya
 *
 */
public abstract class DlogGroupEC extends DlogGroupAbs{

	protected static  Properties nistEC; // properties object to hold nist parameters
	private final static  String PROPERTIES_FILES_PATH = "C:/development/SDK/Code/bin/propertiesFiles/";
	protected String nistCurveName = null; // name of the curve
	
	static{
		try {
			nistEC = new Properties();
			/*load the EC file*/
			File file = new File (PROPERTIES_FILES_PATH + "EC.properties");
			
			FileInputStream in=  new FileInputStream(file);
			
			nistEC.load(in);
			
			in.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
	
	/**
	 * Checks if the given key is valid
	 * @param key - curve name
	 * @return true if valid. false, otherwise
	 */
	protected boolean checkNistNameValidity(String key){
	
		if (nistEC.containsKey(key)){ //if the properties object contains the name (key)- valid
			return true;
		} else{
			return false;
		}
	}
	
	/**
	 * Check that the order, generator end groupDesc are valid or not.
	 * if the group was built with NIST curve - compare the parameters to the parameters in the file
	 * else - run a specific check for generator, order according to the group parameters.
	 * @return true if valid, false otherwise.
	 */
	public boolean validateGroup(){
		boolean valid = false;
		// nistCurveName is null if the curve is not NIST curve
		if (nistCurveName == null){
			/* check specifically the order and generator */
			if (isGenerator() && isOrder() && isParams())
				valid = true;
		}
		/* check that the values matches the file parameters */
		else if (validateNistParams() && validateNistGenerator() && validateNistOrder())
					valid = true;
		return valid;
	}

	protected abstract boolean isOrder();
	protected abstract boolean isParams();
	protected abstract boolean validateNistParams();
	protected abstract boolean validateNistGenerator();
		
	/**
	 * validate that the order of this curve is as expected
	 * @return true if the order is valid. false, otherwise
	 */
	private boolean validateNistOrder() {
		//get the expected order
		BigInteger order = new BigInteger(nistEC.getProperty(nistCurveName+"r"));
		/*compare the current order to the expected one.
		 * if equal - return true.
		 * else - return false.
		 */
		if (q.equals(order))
			return true;
		else 
			return false;
	}
}
