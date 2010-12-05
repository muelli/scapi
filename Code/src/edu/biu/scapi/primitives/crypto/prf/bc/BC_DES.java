/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf.bc;

import org.bouncycastle.crypto.engines.DESEngine;

/** 
 * @author LabTest
 */
public class BC_DES extends BC_PRP {

	/** 
	 * @param bcBlockCipher
	 */
	public BC_DES() {

		super(new DESEngine());
	}
}