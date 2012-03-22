package edu.biu.scapi.anonymousForums;

public class AnonymousForumLongTermKeyPair {
	AnonymousForumLongTermPublicKey publicKey;
	AnonymousForumLongTermPrivateKey privateKey;
	public AnonymousForumLongTermKeyPair(
			AnonymousForumLongTermPublicKey publicKey,
			AnonymousForumLongTermPrivateKey privateKey) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	public AnonymousForumLongTermPublicKey getPublicKey() {
		return publicKey;
	}
	public AnonymousForumLongTermPrivateKey getPrivateKey() {
		return privateKey;
	}
	
	
	
}
