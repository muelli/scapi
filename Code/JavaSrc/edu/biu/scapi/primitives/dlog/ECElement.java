package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;


/**
 * Marker interface. Every class that implements it, is signed as an elliptic curve point
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ECElement extends GroupElement{
	/**
	 * This function returns the x coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * @return x coordinate of (x,y) point
	 */
	public BigInteger getX();
	
	/**
	 * This function returns the y coordinate of the (x,y) point which is an element of a given elliptic curve.
	 * @return y coordinate of (x,y) point
	 */
	public BigInteger getY();
}
