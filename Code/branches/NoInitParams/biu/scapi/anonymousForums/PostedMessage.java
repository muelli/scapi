package edu.biu.scapi.anonymousForums;

import java.math.BigInteger;

public class PostedMessage {
	
	byte[] msg;
	BigInteger polynomialEval;
	ZKProof[] arrayOfProofs;
	public PostedMessage(byte[] msg, BigInteger polynomialEval,
			ZKProof[] arrayOfProofs) {
		super();
		this.msg = msg;
		this.polynomialEval = polynomialEval;
		this.arrayOfProofs = arrayOfProofs;
	}
	
	public byte[] getMsg() {
		return msg;
	}
	public BigInteger getPolynomialEval() {
		return polynomialEval;
	}
	public ZKProof[] getArrayOfProofs() {
		return arrayOfProofs;
	}
	
	

}
