package edu.biu.scapi.primitives.trapdoor_permutation;

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
