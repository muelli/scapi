/**
 * 
 * The FactoriesUtility class as its name indicates is a utility class used by all the factories. 
 * The actual creation of the object is done with this class in the public function getObject. 
 * All the factories call this method and cast the created object to the actual type they need to return. 
 */
package edu.biu.scapi.tools.Factories;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;


import edu.biu.scapi.generals.Logging;

/** 
 * @author LabTest
 */
public class FactoriesUtility {
	private Properties defaultProviderMap;
	private Properties algsInType;
	
	private static final String PROPERTIES_FILES_PATH = "/propertiesFiles/";

	
	/** 
	 * Loads the files to the properties attributes.
	 * @param defaultProviderFileName the file name from which to load the default provider properties from. 
	 * 									*Note that this can be null. for example the BCFactory does not need to pass
	 * 									 default provider for each implementation. 
	 * @param algsInTypeFileName the file name from which to load the algorithms in type properties from
	 */
	public FactoriesUtility(String defaultProviderFileName,
			String algsInTypeFileName) {
		
		try {
			//load algorithms classes
			loadAlgsInType(algsInTypeFileName);
			
			//if this class is used by a class that does not need default provider, it will not pass a name to such a file
			if(defaultProviderFileName!=null)
				//load default provider names for each algorithm name
				loadDefaultProvider(defaultProviderFileName);
		} catch (FileNotFoundException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IOException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		
	}
	
	/** 
	 * parseAlgNames : The string algName should be of the form “alg1Name(alg2Name, …,algnName)”, where n can be any number greater than zero. 
	 * (If n = zero, then AlgDetails.Name = null and AlgDetails.tail = null. If n = 1 then  AlgDetails.Name = “alg1” and AlgDetails.params=null. 
	 * If n >=2 then AlgDetails.Name = alg1 and AlgDetails.tail = [alg2Name , …,algnName)])
	 * •	Parse the string and return the following:
	 * o	If n = 0, then AlgDetails.name = null and AlgDetails.params = null. 
	 * o	If n = 1, then AlgDetails.name = “alg1” and AlgDetails.params =null. 
	 * If n >=2, then AlgDetails.name = “alg1” and AlgDetails.params = [alg2Name, …,algnName]
	 * 
	 * @param algNames a string of the form "alg1Name(alg2Name,alg3Name(alg4Name, alg5Name)" where alg1 is the main algorithm which takes
	 * 					 other algorithms as parameters (complex algorithm) and alg3 is also a complex algorithm that takes
	 * 					 alg4 and alg5 simple algorithms as parameters. 
	 * @return
	 */
	private AlgDetails parseAlgNames(String algNames) {

		//create a new algDetails object to return
		AlgDetails algDetails = new AlgDetails();
		
		//use the parser to separate the string into the main algorithm and the params 
		AlgorithmStringParser parser = new AlgorithmStringParser(algNames);
		
		//get the main algorithm
		algDetails.name = parser.getAlgName();
		
		//get the parameters
		algDetails.params = parser.getParsedParams();
		
		return algDetails;
		
	}

	/** 
	 * @param algName the algorithm for which to check validity for
	 * @return true if the algorithm exists in the defaultProviderMap, else false.
	 */
	private boolean checkValidity(String algName) {

		return algsInType.containsKey(algName);
	}

	/** 
	 * @param provider the required provider of the requested algorithm
	 * @param algName the algorithm name
	 * @return the concatenation of provider+algorithm.
	 */
	private String prepareKey(String provider, String algName) {
		
		return provider+algName;

	}

	/**
	 * Loads the names of the algorithms concatenated to the provider and the respecting name of the corresponing class name
	 * @param algsInTypeFileName the name of the file to load
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadAlgsInType(String algsInTypeFileName) throws FileNotFoundException, IOException {
		
		//instantiate the default provider properties
		algsInType = new Properties();
        
        /*
        //the algorithm classes file should look something like this:
        
        "# Bouncy Castle 
        BcAES = BcAES
        ScAES = AES " */
        
		//load the algsInTypeFileName file
		InputStream in=  (InputStream) getClass().getResourceAsStream(PROPERTIES_FILES_PATH + algsInTypeFileName);
		
		algsInType.load(in);
	}

	/**
	 *  Loads the names of the algorithms with the corresponding default providers 
	 *  @param defaultProviderFileName the name of the file to load
	 * @throws IOException 
	 * @throws FileNotFoundException  
	 */
	private void loadDefaultProvider(String defaultProviderFileName) throws FileNotFoundException, IOException {
		
		//instantiate the default provider properties
		defaultProviderMap = new Properties();
        
        /*
        //the default provider file should look something like this:
        
        "# Bouncy Castle 
        DES = BC
        AES = Sc " */
        
		//load the defaultProviderFileName file
		InputStream in=  (InputStream) getClass().getResourceAsStream(PROPERTIES_FILES_PATH + defaultProviderFileName);
		
		algsInType.load(in);
		
		
	}

	/** 
	 * This function may return different libraries for different algorithms. 
	 * For example, it may return "Crypto++" when requesting a Rabin trapdoor permutation and "BC" when requesting an AES implementation. 
	 * The decision on which implementation to return will be based on the available implementations, 
	 * on performance and other relevant reasons. 
	 * 
	 * @param algName the algorithm name to get the default provider for
	 * @return the default provider for the algorithm specified with the key algName
	 */
	public String getDefaultImplProvider(String algName) {
		
		return defaultProviderMap.getProperty(algName);
	}

	/** 
	 * pseudocode:
	 * This function returns an Object instantiation of algName algorithm for the specified provider.
	 * •	Parse algorithm name in order to get AlgDetails.
	 * •	Check validity of AlgDetails.name. If not valid, throw exception.
	 * •	Prepare key for map by concatenating provider + algName.
	 * •	Get relevant class name from properties map with the key obtained.
	 * •	Get an object of type Class representing our algorithm. (Class algClass).
	 * •	Retrieve a Constructor of algClass that accepts t parameters of type String, while t=tailVector.length.
	 * •	Create an instance of type algClass by calling the above Constructor. Pass as a parameter the “tailVector” in AlgDetails. The call Constructor.newInstance returns an object of type Object. (For example, if algName is a series of algorithms: "HMAC(SHA1)", the function creates an HMAC object and passes the tail – "SHA1" to the instance of HMAC. HMAC should be a class that takes as argument a string and in its constructor uses the factories to create the hash object. In this case, where there is a tail, the getObject function passes the String "SHA1" by retrieving a constructor that gets a String. If there is no such constructor, an exception will be thrown). 
	 * •	 Return the object created.
	 *
	 * @param provider the required provider name
	 * @param algName the required algorithm name
	 * @return an object of the class that was determined by the algName + provider
	 */
	public Object getObject(String provider, String algName) throws IllegalArgumentException{
		
		//get the parsed algorithm details
		AlgDetails algDetails = parseAlgNames(algName);
		
		//check the validity of the request. Meaning, the requested algorithm does exist. 
		boolean valid = checkValidity(provider + algDetails.name);
		
		//if invalid throw IllegalArgumentException exception
		if(!valid){
			throw (new IllegalArgumentException("Algorithm " + algDetails.name + " is not supported for provider " + provider));
		}
		
		//get the key as written in the property file
		String keyToMap = prepareKey(provider, algDetails.name);
		
		//get the related algorithm class name
		String className = algsInType.getProperty(keyToMap);
		
		Class algClass  = null;//will hold an Object of type Class representing our alg class
		Object newObj = null;//will the final create algorithm object
		try {
			//get the class object thru the name of the algorithm class
			algClass = Class.forName(className);
	
			//fill the classes of strings with the length of the vector. This will ensure that we get the right/relevant
			//constructor
			int size = algDetails.params.size();
			Class[] classes = new Class[size]; 
			
			//fill the array with String classes
			for(int i=0;i<size;i++){
				classes[i] = String.class;
			}
			
			//get the constructor that has <code>classes.length<code> number of arguments of string type  
			Constructor constructor = algClass.getConstructor(classes);
			
			
			//prepare parameters for constructor:
			//get the vector of parameters from the algorithm details object.
			//create an instance of type algClass by calling the obtained constructor:
			//NOTE (Secure coding) : The command newInstance with a parameter contains a potential security risk of creating undesired objects
			//however, the parameters passed to the newInstance function are only those of algorithms we allow. That is, the classes that 
			//can be created here are limited and controlled.
			 newObj = constructor.newInstance(algDetails.params.toArray());
			 
		} catch (SecurityException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (NoSuchMethodException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (ClassNotFoundException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IllegalArgumentException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (InstantiationException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IllegalAccessException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (InvocationTargetException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		return  newObj;
		
	}

	

	/** 
	 * 
	 * @param algName the required algorithm name
	 * @return an object of the class that was determined by the algName + the default provider for that algorithm
	 */
	public Object getObject(String algName) throws IllegalArgumentException{

		//no provider has been supplied. Get the provider name from the default implementation properties.
		String provider = getDefaultImplProvider(algName);
		
		return getObject(provider, algName);
	}
	
	//nested class:
	class AlgDetails{
		public String name;					//the name  of the main algorithm
		public Vector<String> params; 		//the other algorithms to use. The params will be passed as an argument to the 
											//constructor of the main algorithm.
	}
	
	//nested class
	
	/**
	 * A utility class that aids to parse 
	 */
	class AlgorithmStringParser{
		
		private String algorithmCommand;
		private String algorithmParamsAsOneString = "";
		private String mainAlgName = "";
		
		/**
		 * AlgorithmParser the constructor
		 * @param algorithmCommand the string to work on
		 */
		public AlgorithmStringParser(String algorithmCommand) {
			
			this.algorithmCommand = algorithmCommand;
			splitToNameAndParamsAsString();
			
		}
		
		/**
		 * 
		 * Counts the number of occurrences of the parameter searchFor in base String
		 * @param searchFor the string for which we wish to count the number of occurrences for
		 * @return the number of occurrences of searchFor in base
		 */
		int occurances(String base, String searchFor){
			
			int len = searchFor.length();
			int result = 0;
			if (len > 0) {
				int start = base.indexOf(searchFor);
				while (start != -1) {
		            result++;
		            start = base.indexOf(searchFor, start+len);
		        }
		    }
			return result;
				
		}
		
		/**
		 * 
		 * Retrieves the main algorithm from the String <code>algorithmCommand<code> and generates the string
		 * <code>algorithmParamsAsOneString<code>.
		 */
		void splitToNameAndParamsAsString()
		{
			
			
			//check if this a complex algorithm command or if it contains only one algorithm
			int index = algorithmCommand.indexOf("(");
			
			if(index==-1){//simple
				algorithmParamsAsOneString = "";
				mainAlgName = algorithmCommand;
			}
			else{
				mainAlgName = (String) algorithmCommand.subSequence(0, index);
				//cut off the first left parenthesis and the last right parenthesis.
				algorithmParamsAsOneString = (String) algorithmCommand.subSequence(index+1, algorithmCommand.length()-1);
				
			}
		}
		
		/**
		 * 
		 * getAlgName :  
		 * @return the main algorithm string
		 */
		String getAlgName()
		{
			return mainAlgName;
		}
		
		
		/**
		 * 
		 * Retrieves the parameters of the algorithm from the String <code>algorithmParamsAsOneString<code>.
		 * @return a vector holding each parameter
		 */
		Vector<String> getParsedParams(){
			
			String tempParam = "";
			
			//a vector that will hold the complex parameters. A parameter can be of the form "a(b,c)" even though
			//it contains "," and is split in the params array.
			Vector<String> finalParams = new Vector<String>();
			//get the parameters into strings. The problems is that we may get more than we should. for example,
			// the string "a(b(c,d)),e"
			String [] params = algorithmParamsAsOneString.split(",");
			
			int paranthesis = 0;
			
			//go over the simple split arguments of params and form the complex params if there are any.
			for(int i=0; i< params.length ; i++){
				
				//concatenate the new param
				tempParam+= params[i];
				
				//count the number of left parenthesis minus the number of right parenthesis
				paranthesis = occurances(tempParam, "(") - occurances(tempParam, ")");
				
				//check that the accumulated string is a parameter or we should concatenate more
				if(paranthesis==0){
					//tempParam contains the full parameter add it to the vector
					if(!tempParam.isEmpty())
						finalParams.add(tempParam);
					//set as empty, we start a new parameter.
					tempParam = "";
				}
				else{
					//return the "," since it would not have been removed
					tempParam =tempParam + ",";
				}
					
			}
			
			return finalParams;
		}
		
		
	}
}