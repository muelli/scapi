package edu.biu.scapi.primitives.dlog;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;


/**
 * This class manages the creation of NIST recommended elliptic curves.
 * We have a properties file which contains the parameters for the curves. 
 * This class upload the file once, and construct a properties object from it.
 * @author Moriya
 *
 */
public abstract class DlogGroupEC extends DlogGroupAbs{

	private  Properties nistProperties; // properties object to hold nist parameters
	protected String PROPERTIES_FILES_PATH = System.getProperty("java.class.path").toString().split(";")[0]+"\\propertiesFiles\\NISTEC.properties";
	
	/**
	 * Initialize the DlogGroup with a curve which does not comply with NIST recommended elliptic curves.
	 * @param fileName - name of the elliptic curves file
	 * @param curveName - name of NIST curve to initialized
	 * @throws IllegalAccessException
	 * @throws IOException - in case there is a problem with the given file
	 */
	public void init(String fileName, String curveName) throws IllegalArgumentException, IOException{
		
		Properties ecProperties;
		
		ecProperties = getProperties(fileName); //get properties object containing the curve data
		
		//checks that the curveName is in the file 
		if(!ecProperties.containsKey(curveName)) { 
			throw new IllegalArgumentException("no such elliptic curve in the given file");
		}
		
		isInitialized = true; 
		doInit(ecProperties, curveName); // set the data and initialize the curve
		
	}

	protected abstract void doInit(Properties ecProperties, String curveName);
		

	protected Properties getProperties(String fileName) throws IOException{
		Properties ecProperties = null;
		
		if(fileName.contains("NISTEC") && nistProperties!=null){
			return nistProperties;
		}
	
		ecProperties = new Properties();
		/*load the EC file*/
		File file = new File (fileName);
		FileInputStream in=  new FileInputStream(file);
		ecProperties.load(in);
		in.close();
		
		if(fileName.contains("NISTEC")){
			nistProperties = ecProperties;
		}

		return ecProperties;
	}
	
	/**
	 * Checks that the order, generator and groupParams are valid or not.
	 * There are two ways to set those parameters. One way is to load them from NIST file, so the parameters are correct. 
	 * The second way is to get the parameters from the user in the init function. In that way, that is the user responsibility to check the validity of the parameters.
	 * In both ways, the parameters we set should be correct. Therefore, currently the function validateGroup does not operate the validity check and always return true.
	 * In the future we may add the validity checks.
	 * @return true.
	 */
	public boolean validateGroup(){
		return true;
	}

	/**
	 * Checks if the given generator is indeed the generator of the group
	 * There are two ways to set the generator. One way is to load it from NIST file, so the generator is correct. 
	 * The second way is to get the generator values from the user in the init function. In that way, that is the user responsibility to check the validity of the parameters.
	 * In both ways, the generator we set should be correct. Therefore, currently the function isGenerator does not operate the validity check and always return true.
	 * Maybe in the future we will add the validity checks.
	 * @return true.
	 */
	public boolean isGenerator(){
		return true;
	}
		
	
}
