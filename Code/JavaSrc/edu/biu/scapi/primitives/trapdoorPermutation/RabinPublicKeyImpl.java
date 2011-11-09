package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;


/**
 * Concrete class of RabinPublicKey
 *
 */
public class RabinPublicKeyImpl extends RabinKeyImpl implements RabinPublicKey {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private BigInteger quadraticResidueModPrime1 = null; //r
	private BigInteger quadraticResidueModPrime2 = null; //s

	/**
	 * Constructor that accept the public key
	 * @param mod
	 * @param r - quadratic residue mod prime1
	 * @param s - quadratic residue mod prime2
	 */
	public RabinPublicKeyImpl (BigInteger mod, BigInteger r, BigInteger s) {
		modulus = mod;
		quadraticResidueModPrime1 = r;
		quadraticResidueModPrime2 = s;
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
	 * @return BigInteger - QuadraticResidueModPrime1 (r)
	 */
	public BigInteger getQuadraticResidueModPrime1() {
		
		return quadraticResidueModPrime1;
	}

	/**
	 * @return BigInteger - QuadraticResidueModPrime2 (s)
	 */
	public BigInteger getQuadraticResidueModPrime2() {
		
		return quadraticResidueModPrime2;
	}

}
