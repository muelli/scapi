/**
 * Project: scapi.
 * Package: edu.biu.scapi.primitives.crypto.prf.bc.
 * File: TripleDES.java.
 * Creation date 10:35:11 AM.
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.primitives.crypto.prf.bc;

import org.bouncycastle.crypto.engines.DESedeEngine;

import edu.biu.scapi.primitives.crypto.prf.TripleDES;

/**
 * @author LabTest
 *
 */
public class BcTripleDES extends BcPRP implements TripleDES{

	/**
	 * Pass the DesedeEngine of BC to the abstract super class
	 */
	public BcTripleDES() {
		
		super(new DESedeEngine());
	}

}
