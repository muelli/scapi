package edu.biu.scapi.anonymousForums;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Vector;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class AnonymousForumSpecificPublicKey implements PublicKey, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5610515153675872092L;
	GroupElement h;
	//Array to hold coefficients: cj = (uj, vj) = (g^rj, (h^rj)*g^aj)
	Vector<GroupElementPair> publicCoefficients;
	ZKProof proof;
	
	
	
	public AnonymousForumSpecificPublicKey(GroupElement h,
			Vector<GroupElementPair> coefficients, ZKProof proof) {
		super();
		this.h = h;
		this.publicCoefficients = coefficients;
		this.proof = proof;
	}

	
	
	
	public GroupElement getH() {
		return h;
	}




	public Vector<GroupElementPair> getCoefficients() {
		return publicCoefficients;
	}

	public ZKProof getProof() {
		return proof;
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
