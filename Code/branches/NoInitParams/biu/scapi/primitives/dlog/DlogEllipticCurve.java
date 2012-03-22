package edu.biu.scapi.primitives.dlog;

import java.io.IOException;
import java.math.BigInteger;

import edu.biu.scapi.exceptions.UnInitializedException;

/**
 * Marker interface. Every class that implements it is signed as elliptic curve.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DlogEllipticCurve extends DlogGroup{

	/**
	 * Sets this DlogGroup to be one of NIST recommended elliptic curve.
	 * @param nistCurveName name of NIST curve to initialize
	 * @throws IllegalArgumentException
	 */
	public void init(String nistCurveName)throws IllegalArgumentException;
	
	/**
	 * Sets this DlogGroup to be an elliptic curve that is not one of NIST curves.
	 * @param fileName - name of the file where the curve parameters are written; the file has to follow the format specified in the manual documentation.
	 * @param curveName - name of the curve
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(String fileName, String curveName) throws IllegalArgumentException, IOException;
	
	/**
	 * Creates a point with the given x,y values 
	 * @param x
	 * @param y
	 * @return the created ECPoint (x,y)
	 * @throws UnInitializedException 
	 */
	public ECElement getElement(BigInteger x, BigInteger y) throws UnInitializedException;
	
	/**
	 * 
	 * @return the infinity point of this dlog group
	 */
	public ECElement getInfinity();
}
