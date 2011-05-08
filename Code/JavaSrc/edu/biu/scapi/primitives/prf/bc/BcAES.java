/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.prf.bc.
 * File: BC_AES.java.
 * Creation date 10:19:00 AM.
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.prf.bc;

import org.bouncycastle.crypto.engines.AESEngine;

import edu.biu.scapi.primitives.prf.AES;

/**
 * @author LabTest
 *
 */
public class BcAES extends BcPRP implements AES{

	/**
	 * Pass the AESEngine of BC to the abstract super class
	 */
	public BcAES() {
		super(new AESEngine());
		
	}

	

}
