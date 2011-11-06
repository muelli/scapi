package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;


/**
 * Marker interface. Every class that implements it is signed as elliptic curve point
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ECElement extends GroupElement{
	public BigInteger getX();
	public BigInteger getY();
}
