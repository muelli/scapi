package edu.biu.scapi.anonymousForums;

import java.math.BigInteger;
import java.security.PrivateKey;

public class AnonymousForumLongTermPrivateKey implements PrivateKey {

	BigInteger alpha;
	
	public AnonymousForumLongTermPrivateKey(BigInteger alpha) {
		super();
		this.alpha = alpha;
	}

	public BigInteger getAlpha() {
		return alpha;
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
