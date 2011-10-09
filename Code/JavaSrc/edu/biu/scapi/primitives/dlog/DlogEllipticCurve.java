package edu.biu.scapi.primitives.dlog;

import java.io.IOException;
import java.math.BigInteger;

import edu.biu.scapi.exceptions.UnInitializedException;

/**
 * Marker interface. Every class that implements it is signed as elliptic curve
 * @author Moriya
 *
 */
public interface DlogEllipticCurve extends DlogGroup{

	/**
	 * Initializes the DlogGroup with one of NIST recommended elliptic curve
	 * @param name - name of NIST curve to initialized
	 * @throws IllegalAccessException
	 */
	public void init(String nistCurveName) throws IllegalAccessException;
	
	/**
	 * Initializes the DlogGroup with elliptic curve other than NIST curves
	 * @param fileName - name of the file where the curve parameters are written
	 * @param curveName - name of the curve
	 * @throws IllegalAccessException
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void init(String fileName, String curveName) throws IllegalAccessException, IllegalArgumentException, IOException;
	
	/**
	 * Creates a point with the given x,y values 
	 * @param x
	 * @param y
	 * @return the created ECPoint (x,y)
	 * @throws UnInitializedException 
	 */
	public ECElement getElement(BigInteger x, BigInteger y) throws UnInitializedException;
}
