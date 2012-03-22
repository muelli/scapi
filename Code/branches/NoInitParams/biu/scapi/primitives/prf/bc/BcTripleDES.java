package edu.biu.scapi.primitives.prf.bc;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.DESedeEngine;

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * Concrete class of prf family for Triple-DES. This class wraps the implementation of Bouncy castle.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcTripleDES extends BcPRP implements TripleDES{

	/**
	 * Passes the DesedeEngine of BC to the abstract super class
	 */
	public BcTripleDES() {
		
		super(new DESedeEngine());
	}
	
	/**
	 * initializes this Triple-DES with secret key.
	 * @param secretKey the secret key
	 * @throws InvalidKeyException 
	 */
	public void init(SecretKey secretKey) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//TripleDes key size should be 128/192 bits 
		if(len!=16 && len!=24){
			throw new InvalidKeyException("TripleDes key size should be 128/192 bits long");
		}
		super.init(secretKey);
	}
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidKeyException {
		int len = secretKey.getEncoded().length;
		//TripleDes key size should be 128/192 bits 
		if(len!=16 && len!=24){
			throw new InvalidKeyException("TripleDes key size should be 128/192 bits long");
		}
		super.init(secretKey, params);
	}

}
