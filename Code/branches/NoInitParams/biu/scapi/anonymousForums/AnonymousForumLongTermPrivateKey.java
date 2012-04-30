package edu.biu.scapi.anonymousForums;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class AnonymousForumLongTermPrivateKey implements PrivateKey, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6754986836509019307L;
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
