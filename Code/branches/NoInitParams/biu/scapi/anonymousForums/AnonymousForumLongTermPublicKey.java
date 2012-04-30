package edu.biu.scapi.anonymousForums;

import java.io.Serializable;
import java.security.PublicKey;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class AnonymousForumLongTermPublicKey implements PublicKey, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -4020203984584907363L;
	GroupElement h;
	ZKProof proof;
	
	public AnonymousForumLongTermPublicKey(GroupElement h, ZKProof proof){
		this.h = h;
		this.proof = proof;
	}
	
	public GroupElement getH() {
		return h;
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
