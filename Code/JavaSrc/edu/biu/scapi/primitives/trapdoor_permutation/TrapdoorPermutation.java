/**
 * A trapdoor permutation is a bijection (1-1 and onto function) that is easy to compute for everyone, 
 * yet is hard to invert unless given special additional information, called the "trapdoor". 
 * The public key is essentially the function description and the private key is the trapdoor.
 */
package edu.biu.scapi.primitives.trapdoor_permutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.TPElement;

/** 
 * @author LabTest
  */
public interface TrapdoorPermutation {
	/** 
	 * Initializes this trapdoor permutation with the keys and the auxiliary parameters
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @param params
	 * @throws IllegalAccessException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws IllegalAccessException;

	/** 
	 * Initializes this trapdoor permutation with the keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException;
	
	/** 
	 * Initializes this trapdoor permutation just with the public key
	 * @param publicKey - public key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException;
	
	/** 
	 * Initializes this trapdoor permutation auxiliary parameters
	 * @param params
	 * @throws IllegalArgumentException 
	 */
	public void init(AlgorithmParameterSpec params) throws IllegalArgumentException;


	/** 
	 * @return the parameter spec of this trapdoor permutation
	 */
	public AlgorithmParameterSpec getParams();

	/** 
	 * @return the public key
	 */
	public PublicKey getPubKey();
	
	/** 
	 * @return mod(N)
	 */
	public BigInteger getModulus();

	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName();

	/** 
	 * Compute the operation of this trapdoor permutation on the TPElement that was accepted
	 * @param tpEl - the input for the computation
	 * @return - the result 
	 * @throws IllegalArgumentException 
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException;

	/** 
	 * Invert the operation of this trapdoor permutation on the TPElement that was accepted
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws IllegalArgumentException 
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException;

	/** 
	 * Compute the hard core predicate of the given tpElement
	 * @param tpEl
	 * @return the hard core predicate 
	 */
	public byte hardCorePredicate(TPElement tpEl);

	/** 
	 * Compute the hard core function of the given tpElement
	 * @param tpEl
	 * @return byte[]
	 */
	public byte[] hardCoreFunction(TPElement tpEl);
	
	
	/** 
	 * Check if the given element is valid to this trapdoor permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * @throws IllegalArgumentException 
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException;
	
	/** 
	 * create random TPElement which is valid to this trapdoor permutation
	 * @return TPElement - the random element 
	 */
	public TPElement getRandomTPElement();
	
	/**
	 * Check if the object is initialized.
	 * @return true if initialized, false if not
	 */
	public boolean IsInitialized();
}