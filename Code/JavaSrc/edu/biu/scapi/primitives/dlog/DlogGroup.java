/**
 * The discrete logarithm problem is as follows: given a generator g of a finite 
 * group G and a random element h in G, find the (unique) integer x such that 
 * g^x = h. In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard. The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.
 */
package edu.biu.scapi.primitives.dlog;


import java.math.BigInteger;

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
	 * @return the generator of that Dlog group
	 */
	public GroupElement getGenerator();
	
	/**
	 * 
	 * @return the GroupDesc of that Dlog group
	 */
	public GroupParams getGroupParams();
	
	/**
	 * 
	 * @return the order of that Dlog group
	 */
	public BigInteger getOrder();
	
	/**
	 * Check if the given element is member of that Dlog group
	 * @param element - 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException;
	
	/**
	 * Check if the order is a prime number
	 * @return true if the order is a prime number. false, otherwise.
	 */
	public boolean isPrimeOrder();
	
	/**
	 * check if the order is greater than 2^numBits
	 * @param numBits
	 * @return true if the order is greater than 2^numBits, false - otherwise.
	 */
	public boolean isOrderGreaterThan(int numBits);
	
	/**
	 * Check if the given generator is indeed the generator of the group
	 * @return true, is the generator is valid, false otherwise.
	 */
	public boolean isGenerator();
	
	/**
	 * Check that the order, generator end groupDesc are valid or not.
	 * @return true if valid, false otherwise.
	 */
	public boolean validateGroup();
	
	/**
	 * Calculate the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException;
	
	/**
	 * Calculate the exponentiate of the given GroupElement
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 */
	public GroupElement exponentiate(BigInteger exponent, GroupElement base) throws IllegalArgumentException;
	
	/**
	 * Multiply two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * throws IllegalArgumentException
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException;
	
	/**
	 * Create a random member of that Dlog group
	 * @return the random element
	 */
	public GroupElement getRandomElement();
	
	/**
	 * Compute the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 */
	public GroupElement simultaneousMultipleExponentiations(GroupElement[] groupElements, BigInteger[] exponentiations);
	
	/**
	 * Compute the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.  
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 */
	public GroupElement multExponentiationsWithSameBase(GroupElement groupElement, int exponent);
}
