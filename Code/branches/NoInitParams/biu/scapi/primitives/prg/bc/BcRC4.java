package edu.biu.scapi.primitives.prg.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.RC4Engine;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prg.RC4;

/**
 * Concrete class of PRF for RC4. This class is a wrapper class for BC implementation of RC4.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public final class BcRC4 extends BcPRG implements RC4{
	
	/**
	 * Passes the RC4Engine of BC to the abstract super class
	 */
	public BcRC4(){
		super(new RC4Engine());
	}
	
	public void init(SecretKey secretKey) {
		
		//sets the parameters
		super.init(secretKey);
		
		//RC4 has a problem in the first 1024 bits. by ignoring these bytes, we bypass this problem.
		byte[] out = new byte[128];
		try {
			getPRGBytes(out, 0, 128);
		} catch (UnInitializedException e) {
			// shouldn't occur since super class initialized this prg
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	public void init(SecretKey secretKey, AlgorithmParameterSpec params) {
		
		//sets the parameters
		super.init(secretKey, params);
		
		//RC4 has a problem in the first 1024 bits. by ignoring these bytes, we bypass this problem.
		byte[] out = new byte[128];
		try {
			getPRGBytes(out, 0, 128);
		} catch (UnInitializedException e) {
			// shouldn't occur since super class initialized this prg
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}
}