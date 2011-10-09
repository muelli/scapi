/**
 * 
 */
package edu.biu.scapi.primitives.prg;

import java.security.spec.AlgorithmParameterSpec;


import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * @author LabTest
 */
public abstract class PseudorandomGeneratorAbs implements PseudorandomGenerator {
	
	protected SecretKey secretKey = null;//secrete key
	protected AlgorithmParameterSpec params = null;//algorithm parameters
	protected boolean isInitialized = false;//until isInitialized() is called set to false.

	/** 
	 * Initializes this prg with the secret key
	 * @param secretKey - the secrete key
	 */
	public void init(SecretKey secretKey) {

		//init the key. Further initialization should be implemented in the derived concrete class.
		isInitialized = true;
		this.secretKey = secretKey;
	}

	/** 
	 * Initializes this prg with the secret key and the auxiliary parameters
	 * @param secretKey
	 * @param params
	 */
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {

		//init the parameters. Further initialization should be implemented in the derived concrete class.
		isInitialized = true;
		this.secretKey = secretKey;
		this.params = params;
	}

	/**
	 * 
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean isInitialized(){
		return isInitialized;
	}
	
	/** 
	 * @return the parameters of this prp
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}

	/** 
	 * @return
	 * @throws UnInitializedException 
	 */
	public SecretKey getSecretKey() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return secretKey;
	}
}