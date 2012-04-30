package edu.biu.scapi.anonymousForums;

import java.io.Serializable;
import java.math.BigInteger;


public class ZKProof implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 478846297872692501L;
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
