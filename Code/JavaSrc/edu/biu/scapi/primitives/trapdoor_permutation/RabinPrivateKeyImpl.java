package edu.biu.scapi.primitives.trapdoor_permutation;

import java.math.BigInteger;


/**
 * Concrete class of RabinPrivateKey
 *
 */
public class RabinPrivateKeyImpl extends RabinKeyImpl implements RabinPrivateKey {

	private BigInteger prime1 = null; 		//p
	private BigInteger prime2 = null; 		//q
	private BigInteger inversePModQ = null; //u

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor that accept the private key
	 * @param mod
	 * @param p - prime1
	 * @param q - prime2
	 * @param u - inverse of prime1 mod prime2
	 */
	public RabinPrivateKeyImpl (BigInteger mod, BigInteger p, BigInteger q, BigInteger u) {
		modulus = mod;
		prime1  = p;
		prime2 = q; 
		inversePModQ = u;
	}
	
	/**
	 * @return the algorithm name
	 */
	public String getAlgorithm() {
		
		return "Rabin";
	}

	/**
	 * @return the encoded key
	 */
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return the format of the encoding
	 */
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @return BigInteger - prime1 (p)
	 */
	public BigInteger getPrime1() {
		return prime1;
	}

	/**
	 * @return BigInteger - prime2 (q)
	 */
	public BigInteger getPrime2() {
		return prime2;
	}

	/**
	 * @return BigInteger - inversePModQ (u)
	 */
	public BigInteger getInversePModQ() {
		return inversePModQ;
	}

}
