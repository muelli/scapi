package edu.biu.scapi.primitives.trapdoor_permutation;

import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;


/**
 * Interface for Rabin public key
 *
 */
public interface RabinPublicKey  extends RabinKey, PublicKey, Key {
	
	/**
	 * @return BigInteger - QuadraticResidueModPrime1 (r)
	 */
	public BigInteger getQuadraticResidueModPrime1();
	
	/**
	 * @return BigInteger - QuadraticResidueModPrime2 (s)
	 */
	public BigInteger getQuadraticResidueModPrime2();
}
