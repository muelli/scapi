/**
 * 
 */
package edu.biu.scapi.primitives.perfectUniversalHash;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
  * @author LabTest
 */
public abstract class PerfectUniversalAbs implements PerfectUniversalHash {
	protected AlgorithmParameterSpec params = null;
	protected SecretKey secretKey = null;
	
	protected boolean isInitialized = false;

	/**
	 * Initialize this perfect universal hash with the auxiliary parameters 
	 * @param params
	 */
	public void init(SecretKey secretKey) {

		isInitialized = true;
		this.secretKey = secretKey;
	}
	
	/** 
	 * Initializes this PerfectUniversalHash with the secret key and the auxiliary parameters.
	 * @param secretKey secret key
	 * @param params algorithm parameters
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params){
		
		isInitialized = true;
		this.params = params;
		this.secretKey = secretKey;
	}


	/**
	 * 
	 * @return the flag isInitialized
	 */
	public boolean isInitialized(){
		return isInitialized;
	}
	
	/** 
	 * @return the parameter spec of this perfect universal hash
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
		
	}
}
