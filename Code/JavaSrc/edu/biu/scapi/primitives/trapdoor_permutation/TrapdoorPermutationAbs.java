/**
 * 
 */
package edu.biu.scapi.primitives.trapdoor_permutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.TPElement;

/** 
 * @author user
 */
public abstract class TrapdoorPermutationAbs implements TrapdoorPermutation {
	
	protected AlgorithmParameterSpec params = null;    //algorithm parameters
	protected PrivateKey privKey = null;               //private key
	protected PublicKey pubKey = null;                 //public key
	protected BigInteger modN = null;
	protected boolean beInit = false;

	/** 
	 * Initializes this trapdoor permutation with the keys and the auxiliary parameters
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @param params
	 * @throws IllegalAccessException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws IllegalAccessException {
		pubKey = publicKey;
		privKey = privateKey;
		this.params = params;
		beInit = true;
	}

	/** 
	 * Initializes this trapdoor permutation with the keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		pubKey = publicKey;
		privKey = privateKey;
	}

	/** 
	 * Initializes this trapdoor permutation just with the public key
	 * @param publicKey - public key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException {
		pubKey = publicKey;
	}
	
	/** 
	 * Initializes this trapdoor permutation auxiliary parameters
	 * @param params
	 * @throws InvalidParameterSpecException 
	 */
	public void init(AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		this.params = params; 
	}

	
	/** 
	 * @return the parameter spec of this trapdoor permutation
	 * @throws UnInitializedException 
	 */
	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}

	/** 
	 * @return the public key
	 * @throws UnInitializedException 
	 */
	public PublicKey getPubKey() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return pubKey;
	}
	
	/** 
	 * @return mod(N)
	 * @throws UnInitializedException 
	 */
	public BigInteger getModulus() throws UnInitializedException{
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return modN;
	}
	
	
	/** 
	 * Compute the hard core predicate of the given tpElement.
	 * One possible implementation of this function is to return the least significant bit of the element. 
	 * We use this implementation both in RSA permutation and in Rabin permutation. 
	 * Thus, We implement it in TrapdoorPermutationAbs and let deriving classes override it as needed. 
	 * @param tpEl 
	 * @return byte - in java, the smallest types are boolean and byte. we chose to return a byte since many 
	 * times we need to concatenate the result of various predicates and it will be easier with a byte 
	 * than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl) {
		//get the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] bytesValue = elementValue.toByteArray();
		
		//return the least significant bit (byte, as we said above)
		return bytesValue[bytesValue.length - 1];
	}

	/** 
	 * Compute the hard core function of the given tpElement.
	 * One possible implementation of this function is to return the log (N) least significant bits of 
	 * the element. We use this implementation both in RSA permutation and in Rabin permutation. 
	 * Thus, We implement it in TrapdoorPermutationAbs and let deriving classes override it as needed. 
	 * @param tpEl -
	 * @return byte[] - log (N) least significant bits
	 */
	public byte[] hardCoreFunction(TPElement tpEl) {
		//get the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] bytesValue = elementValue.toByteArray();
		
		//the number of bytes to get the log (N) least significant bits
		double logBits = (modN.bitCount()/2);  //log N bits
		int logBytes = (int) Math.ceil(logBits/8); //log N bytes
		
		//return the min(mod(N),bytesValue.length) least significant bits
		int size = Math.min(logBytes, bytesValue.length);
		byte[] LSBytes = new byte[size];
		//copy the bytes to the output array
		for (int i=size-1; i>=0; i--)
			LSBytes[i] = bytesValue[i];
		return LSBytes;
	
	}
	
	/**
	 * Check if the object is initialized.
	 * @return true if initialized, false if not
	 */
	public boolean IsInitialized() {
		return beInit;
	}
	
	

}