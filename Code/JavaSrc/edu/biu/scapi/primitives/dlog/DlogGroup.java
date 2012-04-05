package edu.biu.scapi.primitives.dlog;


import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
* This is the general interface for the discrete logarithm group. Every class in the DlogGroup family implements this interface.
* <p>
* The discrete logarithm problem is as follows: given a generator g of a finite 
* group G and a random element h in G, find the (unique) integer x such that 
* g^x = h.<p> 
* In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard.<p> 
* The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.
* 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)

 *
 */
public interface DlogGroup {

	/**
	 * Initialize this DlopGroup with the given parameters.
	 * In case of Zp group the parameters should be of type ZpGroupParams.
	 * In elliptic curves case the parameters should be of type ECParameterSpec
	 * @param params used to initialize this group
	 * @throws IOException 
	 * @throws IllegalArgumentException in case there is a problem with the given file
	 */
	public void init(AlgorithmParameterSpec params) throws IllegalArgumentException, IOException;
	
	/**
	 * Checks if this DlogGroup object has been previously initialized.<p> 
	 * To initialize the object the init function has to be called with corresponding parameters after construction.
	 * 
	 * @return <code>true<code> if the object was initialized;
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isInitialized();

	/**
	 * Each concrete class implementing this interface returns a string with a meaningful name for this type of Dlog group. 
	 * For example: "elliptic curve over F2m" or "Zp*"
	 * @return the name of the group type
	 */
	public String getGroupType();
	
	/**
	 * The generator g of the group is an element of the group such that, when written multiplicatively, every element of the group is a power of g.
	 * @return the generator of this Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupElement getGenerator() throws UnInitializedException;
	
	/**
	 * GroupParams is a structure that holds the actual data that makes this group a specific Dlog group.<p> 
	 * For example, for a Dlog group over Zp* what defines the group is p. 
	 * 
	 * @return the GroupDesc of that Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupParams getGroupParams() throws UnInitializedException;
	
	/**
	 * 
	 * @return the order of this Dlog group
	 * @throws UnInitializedException 
	 */
	public BigInteger getOrder() throws UnInitializedException;
	
	/**
	 * 
	 * @return the identity of this Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupElement getIdentity() throws UnInitializedException;
	
	/**
	 * Checks if the given element is a member of this Dlog group
	 * 
	 * @param element possible group element for which to check that it is a member of this group
	 * 
	 * @return <code>true<code> if the given element is a member of this group; <code>false<code> otherwise.
	 * 
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException
	 */
	public boolean isMember(GroupElement element) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Checks if the order is a prime number
	 * 
	 * @return <code>true<code> if the order is a prime number; <code>false<code> otherwise.
	 * 
	 * @throws UnInitializedException
	 */
	public boolean isPrimeOrder() throws UnInitializedException;
	
	/**
	 * Checks if the order of this group is greater than 2^numBits
	 * @param numBits
	 * @return <code>true<code> if the order is greater than 2^numBits; <code>false<code> otherwise.
	 * @throws UnInitializedException
	 */
	public boolean isOrderGreaterThan(int numBits) throws UnInitializedException;
	
	/**
	 * Checks if the element set as the generator is indeed the generator of this group.
	 * The generator is set upon calling the init function of this group. <p>
	 * Therefore, if init hasn't been called this function throws an UnInitializedException.
	 * @return <code>true<code> if the generator is valid; <code>false<code> otherwise.
	 * @throws UnInitializedException
	 */
	public boolean isGenerator() throws UnInitializedException;
	
	/**
	 * Checks parameters of this group to see if they conform to the type this group is supposed to be. 
	 * @return <code>true<code> if valid; <code>false<code> otherwise.
	 * @throws UnInitializedException
	 */
	public boolean validateGroup() throws UnInitializedException;
	
	/**
	 * Calculates the inverse of the given GroupElement.
	 * @param groupElement to invert
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException
	 **/
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Raises the base GroupElement to the exponent. The result is another GroupElement.
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1, GroupElement groupElement2) throws IllegalArgumentException, UnInitializedException;
	
	/**
	 * Creates a random member of this Dlog group
	 * @return the random element
	 * @throws UnInitializedException 
	 */
	public GroupElement getRandomElement() throws UnInitializedException;
	
	/**
	 * Computes the product of several exponentiations with distinct bases 
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
	 * Computes the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.<p>
	 * Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function 
	 * since there is no point to keep anything in memory if we have no intention to use it. 
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 * @throws UnInitializedException 
	 */
	public GroupElement exponentiateWithPreComputedValues(GroupElement groupElement, BigInteger exponent) throws UnInitializedException;
	
	/**
	 * Converts a byte array to a GroupElement.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 * @throws UnInitializedException 
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString) throws UnInitializedException;
	
	/**
	 * Convert a GroupElement to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement);
	
}
