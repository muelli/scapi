/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prg.bc;

import org.bouncycastle.crypto.StreamCipher;

/** 
 * @author LabTest
 */
public class BC_RC4 extends BC_PRG {
	
	public BC_RC4(StreamCipher streamCipher){
		super(streamCipher);
	}
}