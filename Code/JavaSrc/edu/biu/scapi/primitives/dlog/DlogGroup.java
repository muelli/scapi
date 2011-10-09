/**
 * The discrete logarithm problem is as follows: given a generator g of a finite 
 * group G and a random element h in G, find the (unique) integer x such that 
 * g^x = h. In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard. The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.
 */
package edu.biu.scapi.primitives.dlog;


import java.math.BigInteger;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * The general interface for discrete logarithm group. every class in DlogGroup family implements that interface.
 * @author Moriya
 *
 */
public interface DlogGroup {

	/**
	 * 
	 * @return true if the object was initialized. Usually this means that the function init was called
	 */
	public boolean isInitialized();

	/**
	 * 
	 * @return the group type
	 */
	public String getGroupType();
	
	/**
	 * 
	 * @return the generator of that Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupElement getGenerator() throws UnInitializedException;
	
	/**
	 * 
	 * @return the GroupDesc of that Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupParams getGroupParams() throws UnInitializedException;
	
	/**
	 * 
	 * @return the order of that Dlog group
	 * @throws UnInitializedException 
	 */
	public BigInteger getOrder() throws UnInitializedException;
	
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Check if the order is a prime number
	 * @return true if the order is a prime number. false, otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isPrimeOrder() throws UnInitializedException;
	
	/**
	 * check if the order is greater than 2^numBits
	 * @param numBits
	 * @return true if the order is greater than 2^numBits, false - otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isOrderGreaterThan(int numBits) throws UnInitializedException;
	
	/**
	 * Check if the given generator is indeed the generator of the group
	 * @return true, is the generator is valid, false otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isGenerator() throws UnInitializedException;
	
	/**
	 * Check that the order, generator end groupDesc are valid or not.
	 * @return true if valid, false otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean validateGroup() throws UnInitializedException;
	
	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 * @throws UnInitializedException 
	 */
	public GroupElement getRandomElement() throws UnInitializedException;
	
	/**
	 * Compute the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 * @throws UnInitializedException 
	 */
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, BigInteger[] exponentiations) throws UnInitializedException;
	
	/**
	 * Compute the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.  
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 * @throws UnInitializedException 
	 */
	public GroupElement multExponentiationsWithSameBase(GroupElement groupElement, int exponent) throws UnInitializedException;
}
