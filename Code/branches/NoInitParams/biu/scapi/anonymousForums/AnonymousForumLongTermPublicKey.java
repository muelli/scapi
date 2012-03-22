package edu.biu.scapi.anonymousForums;

import java.security.PublicKey;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class AnonymousForumLongTermPublicKey implements PublicKey {

	GroupElement h;
	
	public AnonymousForumLongTermPublicKey(GroupElement h){
		this.h = h;
	}
	
	public GroupElement getH() {
		return h;
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
