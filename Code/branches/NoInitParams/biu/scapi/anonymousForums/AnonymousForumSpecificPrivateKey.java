package edu.biu.scapi.anonymousForums;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Vector;

public class AnonymousForumSpecificPrivateKey implements PrivateKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8320560961565124528L;
	Vector<BigInteger> coefficients;
	Vector<BigInteger> randomExponents;
	
	
	
	public AnonymousForumSpecificPrivateKey(Vector<BigInteger> coefficients,
			Vector<BigInteger> randomExponents) {
		super();
		this.coefficients = coefficients;
		this.randomExponents = randomExponents;
	}
	
	

	public Vector<BigInteger> getCoefficients() {
		return coefficients;
	}



	public Vector<BigInteger> getRandomExponents() {
		return randomExponents;
	}



	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

}
