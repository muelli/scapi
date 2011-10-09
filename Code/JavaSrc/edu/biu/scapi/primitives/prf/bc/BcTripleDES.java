/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.prf.bc.
 * File: TripleDES.java.
 * Creation date 10:35:11 AM.
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.prf.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.DESedeEngine;

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * @author LabTest
 *
 */
public final class BcTripleDES extends BcPRP implements TripleDES{

	/**
	 * Pass the DesedeEngine of BC to the abstract super class
	 */
	public BcTripleDES() {
		
		super(new DESedeEngine());
	}
	
	public void init(SecretKey secretKey) {
		int len = secretKey.getEncoded().length;
		if(len!=16 && len!=24){
			throw new IllegalArgumentException("TripleDes key size should be 16/24/32 bytes");
		}
		super.init(secretKey);
	}
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException{
		int len = secretKey.getEncoded().length;
		if(len!=16 || len!=24){
			throw new IllegalArgumentException("TripleDes key size should be 16/24/32 bytes");
		}
		super.init(secretKey, params);
	}

}
