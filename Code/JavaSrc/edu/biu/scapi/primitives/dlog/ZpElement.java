package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;

/**
 * Marker interface. Every class that implements it is signed as Zp* element
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface ZpElement extends GroupElement{
	public BigInteger getElementValue();
}
