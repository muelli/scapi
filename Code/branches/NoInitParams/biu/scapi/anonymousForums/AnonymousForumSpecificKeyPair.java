package edu.biu.scapi.anonymousForums;

public class AnonymousForumSpecificKeyPair {
	AnonymousForumSpecificPublicKey publicKey;
	AnonymousForumSpecificPrivateKey privateKey;
	
	public AnonymousForumSpecificKeyPair(
			AnonymousForumSpecificPublicKey publicKey,
			AnonymousForumSpecificPrivateKey privateKey) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public AnonymousForumSpecificPublicKey getPublicKey() {
		return publicKey;
	}

	public AnonymousForumSpecificPrivateKey getPrivateKey() {
		return privateKey;
	}
	
	
	
	
}
