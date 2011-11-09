package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;


/**
 * Concrete class of RabinKey
 *
 */
public abstract class RabinKeyImpl implements RabinKey{

	protected BigInteger modulus = null;
	
	/**
	 * @return BigInteger - the modulus
	 */
	public BigInteger getModulus() {
		
		return modulus;
	}
}
