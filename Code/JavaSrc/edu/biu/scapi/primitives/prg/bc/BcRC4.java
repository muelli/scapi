/**
 * 
 */
package edu.biu.scapi.primitives.prg.bc;

import org.bouncycastle.crypto.engines.RC4Engine;

import edu.biu.scapi.primitives.prg.RC4;

/** 
 * @author LabTest
 */
public final class BcRC4 extends BcPRG implements RC4{
	
	public BcRC4(){
		super(new RC4Engine());
	}
}