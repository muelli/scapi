/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.prf.bc.
 * File: BC_AES.java.
 * Creation date 10:19:00 AM.
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.prf.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.AESEngine;

import edu.biu.scapi.primitives.prf.AES;

/**
 * @author LabTest
 *
 */
public final class BcAES extends BcPRP implements AES{

	/**
	 * Pass the AESEngine of BC to the abstract super class
	 */
	public BcAES() {
		super(new AESEngine());
		
	}

	public void init(SecretKey secretKey) {
		int len = secretKey.getEncoded().length;
		if(len!=16 && len!=24 && len!=32){
			throw new IllegalArgumentException("AES key size should be 16/24/32 bytes");
		}
		super.init(secretKey);
	}
	
	public void init(SecretKey secretKey, AlgorithmParameterSpec params) throws InvalidParameterSpecException{
		int len = secretKey.getEncoded().length;
		if(len!=16 || len!=24 || len!=32){
			throw new IllegalArgumentException("AES key size should be 16/24/32 bytes");
		}
		super.init(secretKey, params);
	}
}
