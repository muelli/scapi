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

/**
 * @author LabTest
 *
 */
public class BC_TripleDES extends BC_PRP {

	/**
	 * Pass the DesedeEngine of BC to the abstract super class
	 */
	public BC_TripleDES() {
		
		super(new DESedeEngine());
		// TODO Auto-generated constructor stub
	}

}
