package edu.biu.scapi.anonymousForums;

import java.math.BigInteger;

import edu.biu.scapi.anonymousForums.ForumUser.GroupElementPair;

public class ZKProof {
	GroupElementPair firstProverMsg;  //(A,B)
	BigInteger challengeMsg; //e
	BigInteger secondProverMsg; //z
	
	public ZKProof(GroupElementPair firstProverMsg, BigInteger challengeMsg,
			BigInteger secondProverMag) {
		super();
		this.firstProverMsg = firstProverMsg;
		this.challengeMsg = challengeMsg;
		this.secondProverMsg = secondProverMag;
	}

	public GroupElementPair getFirstProverMsg() {
		return firstProverMsg;
	}

	public BigInteger getChallengeMsg() {
		return challengeMsg;
	}

	public BigInteger getSecondProverMag() {
		return secondProverMsg;
	}
	
	

}
