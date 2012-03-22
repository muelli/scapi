package edu.biu.scapi.anonymousForums;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Vector;

import edu.biu.scapi.anonymousForums.ForumUser.GroupElementPair;
import edu.biu.scapi.primitives.dlog.GroupElement;

public class AnonymousForumSpecificPublicKey implements PublicKey {

	GroupElement h;
	//Array to hold coefficients: cj = (uj, vj) = (g^rj, (h^rj)*g^aj)
	Vector<GroupElementPair> publicCoefficients;
	
	
	
	
	public AnonymousForumSpecificPublicKey(GroupElement h,
			Vector<GroupElementPair> coefficients) {
		super();
		this.h = h;
		this.publicCoefficients = coefficients;
	}

	
	
	
	public GroupElement getH() {
		return h;
	}




	public Vector<GroupElementPair> getCoefficients() {
		return publicCoefficients;
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
