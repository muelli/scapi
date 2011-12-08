package edu.biu.scapi.primitives.trapdoorPermutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * This class implements some common functionality of trapdoor permutation.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public abstract class TrapdoorPermutationAbs implements TrapdoorPermutation {
	
	protected AlgorithmParameterSpec params = null;    //algorithm parameters
	protected PrivateKey privKey = null;               //private key
	protected PublicKey pubKey = null;                 //public key
	protected BigInteger modN = null;				   //modulus
	protected boolean isInitialized = false;		   // indicates if this object is initialized or not. Set to false until init is called

	
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) {
		//sets the class members with the parameters
		pubKey = publicKey;
		privKey = privateKey;
		this.params = params;
		isInitialized = true; // mark this object as initialized
	}

	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		//sets the class members with the keys
		pubKey = publicKey;
		privKey = privateKey;
		isInitialized = true; // mark this object as initialized
	}

	public void init(PublicKey publicKey) throws InvalidKeyException {
		//sets the class member with the public key
		pubKey = publicKey;
		isInitialized = true; // mark this object as initialized
	}
	
	public void init(AlgorithmParameterSpec params) throws InvalidParameterSpecException {
		//sets the class member with the params
		this.params = params; 
		isInitialized = true; // mark this object as initialized
	}
	

	public boolean IsInitialized() {
		return isInitialized;
	}

	public AlgorithmParameterSpec getParams() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return params;
	}

	public PublicKey getPubKey() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return pubKey;
	}
	
	public BigInteger getModulus() throws UnInitializedException{
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return modN;
	}
	
	
	/** 
	 * Compute the hard core predicate of the given tpElement, by return the least significant bit of the element. 
	 *
	 * @param tpEl the element to compute the hard core predicate on
	 * @return byte the hard core predicate. In java, the smallest types are boolean and byte. 
	 * We chose to return a byte since many times we need to concatenate the result of various predicates 
	 * and it will be easier with a byte than with a boolean.
	 */
	public byte hardCorePredicate(TPElement tpEl) {
		/*
		 *  We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] bytesValue = elementValue.toByteArray();
		
		//returns the least significant bit (byte, as we said above)
		return bytesValue[bytesValue.length - 1];
	}

	/** 
	 * Computes the hard core function of the given tpElement, by return the log (N) least significant bits of 
	 * the element. 
	 * @param tpEl the element to compute the hard core function on
	 * @return byte[] - log (N) least significant bits
	 */
	public byte[] hardCoreFunction(TPElement tpEl) {
		/*
		 * We use this implementation both in RSA permutation and in Rabin permutation. 
		 * Thus, We implement it in TrapdoorPermutationAbs and let derived classes override it if needed. 
		 */
		//gets the element value as byte array
		BigInteger elementValue = tpEl.getElement();
		byte[] elementBytesValue = elementValue.toByteArray();
		
		//the number of bytes to get the log (N) least significant bits
		double logBits = (modN.bitCount()/2);  //log N bits
		int logBytes = (int) Math.ceil(logBits/8); //log N bites in bytes
		
		//if the element length is less than log(N), the return byte[] should be all the element bytes
		int size = Math.min(logBytes, elementBytesValue.length);
		byte[] leastSignificantBytes = new byte[size];
		//copies the bytes to the output array
		System.arraycopy(elementBytesValue, elementBytesValue.length-size, leastSignificantBytes, 0, size);
		return leastSignificantBytes;
	
	}

}