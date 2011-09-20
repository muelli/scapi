package edu.biu.scapi.primitives.dlog.groupParams;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public abstract class GroupParams implements AlgorithmParameterSpec {

	protected BigInteger q; //the group order

	public BigInteger getQ() { 
		return q;
	}
}
