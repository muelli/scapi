package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;

/**
 * Interface for Rabin Keys
 * 
 *
 */
public interface RabinKey {
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus();
}
