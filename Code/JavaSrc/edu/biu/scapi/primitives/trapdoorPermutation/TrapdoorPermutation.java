package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This interface is the general interface of trapdoor permutation. Every class in this family should implement this interface.
 * 
 * A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone, 
 * yet is hard to invert unless given special additional information, called the "trapdoor". 
 * The public key is essentially the function description and the private key is the trapdoor.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
  */
public interface TrapdoorPermutation {
	/** 
	 * Initializes this trapdoor permutation with the keys and the auxiliary parameters
	 * @param publicKey  public key
	 * @param privateKey  private key
	 * @param params  auxiliary parameters
	 * @thros UnsupportedOperationException in some trapdoor permutations this function is not supported
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws UnsupportedOperationException;

	/** 
	 * Initializes this trapdoor permutation with the keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException  if the keys are invalid for this trapdoor permutation
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException;
	
	/** 
	 * Initializes this trapdoor permutation with the public key.
	 * After this initialization, this object can do compute but not invert.
	 * This initialization is for user that wants to encrypt a message using the public key but deosn't want to decrypt a message.
	 * @param publicKey - public key
	 * @throws InvalidKeyException  if the key is invalid for this trapdoor permutation
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException;
	
	/** 
	 * Initializes this trapdoor permutation with auxiliary parameters
	 * @param params  auxiliary parameters
	 * @throws InvalidParameterSpecException if the params are invalid for this trapdoor permutation
	 */
	public void init(AlgorithmParameterSpec params) throws InvalidParameterSpecException;

	/**
	 * An object trying to use an instance of trapdoor permutation needs to check if it has already been initialized.
	 * @return true if the object was initialized by calling the function init.
	 */
	public boolean IsInitialized();
	
	/** 
	 * @return the parameter spec of this trapdoor permutation
	 * @throws UnInitializedException if this object is not initialized
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException;

	/** 
	 * @return the public key
	 * @throws UnInitializedException if this object is not initialized
	 */
	public PublicKey getPubKey() throws UnInitializedException;
	
	/** 
	 * Some of the trapdoor permutations are written as exponentiation modulo a composite number. This function returns this modulus. 
	 * @return the modulus of the permutation. 
	 * @throws UnInitializedException if this object is not initialized
	 */
	public BigInteger getModulus() throws UnInitializedException;

	/** 
	 * @return the algorithm name. for example - RSA, Rabin.
	 */
	public String getAlgorithmName();

	/** 
	 * Computes the operation of this trapdoor permutation on the given TPElement.
	 * @param tpEl - the input for the computation
	 * @return - the result TPElement from the computation
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 * @throws UnInitializedException  if this object is not initialized
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException, UnInitializedException;

	/** 
	 * Inverts the operation of this trapdoor permutation on the given TPElement.
	 * @param tpEl - the input to invert
	 * @return - the result TPElement from the invert operation
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 * @throws UnInitializedException if this object is not initialized
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException, UnInitializedException;

	/** 
	 * Computes the hard core predicate of the given tpElement. <p>
	 * A hard-core predicate of a one-way function f is a predicate b (i.e., a function whose output is a single bit) 
	 * which is easy to compute given x but is hard to compute given f(x).
	 * In formal terms, there is no probabilistic polynomial time algorithm that computes b(x) from f(x) 
	 * with probability significantly greater than one half over random choice of x.
	 * @param tpEl the input to the hard core predicate
	 * @return byte the hard core predicate. In java, the smallest types are boolean and byte. 
	 * We chose to return a byte since many times we need to concatenate the result of various predicates 
	 * and it will be easier with a byte than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl);

	/** 
	 * Computes the hard core function of the given tpElement.
	 * A hard-core function of a one-way function f is a function g 
	 * which is easy to compute given x but is hard to compute given f(x).
	 * In formal terms, there is no probabilistic polynomial time algorithm that computes g(x) from f(x) 
	 * with probability significantly greater than one half over random choice of x.
	 * @param tpEl the input to the hard core function
	 * @return byte[] the result of the hard core function
	 */
	public byte[] hardCoreFunction(TPElement tpEl);
	
	
	/** 
	 * Checks if the given element is valid for this trapdoor permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element.
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws IllegalArgumentException if the given element is invalid for this permutation
	 * @throws UnInitializedException if this object is not initialized
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException, UnInitializedException;
	
	/** 
	 * creates a random TPElement that is valid for this trapdoor permutation
	 * @return TPElement - the created random element 
	 * @throws UnInitializedException if this object is not initialized
	 */
	public TPElement getRandomTPElement() throws UnInitializedException;
	
}