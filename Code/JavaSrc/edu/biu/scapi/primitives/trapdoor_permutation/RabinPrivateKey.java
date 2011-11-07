package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;


/**
 * Interface for Rabin private key
 *
 */
public interface RabinPrivateKey extends RabinKey, PrivateKey, Key {

	/**
	 * @return BigInteger - prime1 (p)
	 */
	public BigInteger getPrime1();
	
	/**
	 * @return BigInteger - prime2 (q)
	 */
	public BigInteger getPrime2();
	
	/**
	 * @return BigInteger - inversePModQ (u)
	 */
	public BigInteger getInversePModQ();
}
