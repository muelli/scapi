package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;

/**
 * General interface for Rabin Keys
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public interface RabinKey {
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus();
}
