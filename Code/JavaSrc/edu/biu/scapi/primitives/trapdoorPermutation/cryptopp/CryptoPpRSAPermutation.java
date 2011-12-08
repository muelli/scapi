package edu.biu.scapi.primitives.trapdoorPermutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.trapdoorPermutation.RSAPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutationAbs;

/**
 * Concrete class of trapdoor permutation of RSA.
 * This class wraps the crypto++ implementation of RSA permutation
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public final class CryptoPpRSAPermutation extends TrapdoorPermutationAbs implements RSAPermutation {

	private long tpPtr; //pointer to the RSA native object
	
	// native functions. These functions are implemented in the CryptoPPJavaInterface dll using the JNI.
	
	//initializes RSA permutation with public and private keys
	private native long initRSAPublicPrivate(byte[] modulus, byte[] pubExponent, byte[] privExponent);
	//initializes RSA permutation with public and crt private keys
	private native long initRSAPublicPrivateCrt(byte[] modulus, byte[] pubExponent, byte[] privExponent, 
									   byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] crt);
	//initializes RSA permutation with public key
	private native long initRSAPublic(byte[] modulus, byte[] pubExponent);
	//initializes RSA permutation randomly
	private native long initRSARandomly(int numBits, byte[] pubExponent);
	
	//returns the algorithm name - RSA
	private native String loadRSAName(long ptr);
	//returns the modulus
	private native byte[] getRSAModulus(long ptr);
	//checks if the given element value is valid for this RSA permutation
	private native boolean checkRSAValidity(long value, long ptr);
	
	//computes RSA permutation
	private native long computeRSA(long tpr, long x);
	//inverts RSA permutation
	private native long invertRSA(long ptr, long y);
	
	//deletes the native object
	private native void deleteRSA(long ptr);
	

	/** 
	 * No such implementation for RSA permutation. throws UnsupportedOperationException.
	 * This RSA implementation can be initialized by two ways:
	 * 1. keys
	 * 2. algorithmParameterSpec
	 * any combination of these ways is not a legal initialization.
	 * @throws UnsupportedOperationException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws UnsupportedOperationException {
		/*initialization of RSA can be done by two ways:
		 * 1. keys
		 * 2. algorithmParameterSpec
		 * any combination of these ways is not a legal initialization.
		 */
		throw new UnsupportedOperationException("no such RSA initialization");

	}
	
	/** 
	 * Initializes this trapdoor permutation with pulic and private keys
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException if the given keys are not RAE keys
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey) || !(privateKey instanceof RSAPrivateKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		/* gets the values of modulus (N), pubExponent (e), privExponent (d)*/
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
		modN = ((RSAKey) publicKey).getModulus();
		
		//if private key is CRT private key
		if (privateKey instanceof RSAPrivateCrtKey)
		{
			//gets all the crt parameters
			RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
			BigInteger p = key.getPrimeP();
			BigInteger q = key.getPrimeQ();
			BigInteger dp = key.getPrimeExponentP();
			BigInteger dq = key.getPrimeExponentQ();
			BigInteger crt = key.getCrtCoefficient();
			
			//initializes the native object
			tpPtr = initRSAPublicPrivateCrt(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
					p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
			
		//if private key is key with N, e, d
		} else {
			
			//init the native object with the RSA parameters - n, e, d
			tpPtr = initRSAPublicPrivate(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
		}
		
		//calls the parent init that sets the keys
		super.init(publicKey, privateKey);
		
	}

	/** 
	 * Initializes this RSA permutation with public key
	 * @param publicKey - public key
	 * @throws InvalidKeyException if the key is not RSA key
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException {
			
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
		RSAPublicKey pub = (RSAPublicKey) publicKey;
		BigInteger pubExponent = pub.getPublicExponent();
		modN = pub.getModulus();
		
		//init the native object with the RSA public parameters - n, e
		tpPtr = initRSAPublic(modN.toByteArray(), pubExponent.toByteArray());

		//calls the parent init
		super.init(publicKey);
	}
	
	/** 
	 * Initializes this RSA permutation randomly
	 * @param params auxiliary parameters
	 * @throws InvalidParameterSpecException if params are not RSA parameter spec
	 */
	public void init(AlgorithmParameterSpec params) throws InvalidParameterSpecException  {
		
		if (!(params instanceof RSAKeyGenParameterSpec)) {
			throw new InvalidParameterSpecException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}
		
		//gets the modulus bits size and public exponent
		int numBits = ((RSAKeyGenParameterSpec) params).getKeysize();
		BigInteger pubExp = ((RSAKeyGenParameterSpec) params).getPublicExponent();

		//init the native object 
		tpPtr = initRSARandomly(numBits, pubExp.toByteArray());
		//sets the mod
		modN = new BigInteger(getRSAModulus(tpPtr));
		
		//calls the parent init
		super.init(params);
	}
	
	/** 
	 * @return the algorithm name - RSA
	 */
	public String getAlgorithmName() {
		
		return loadRSAName(tpPtr);
	}

	/** 
	 * Computes the RSA permutation on the given TPElement
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws UnInitializedException if this object is not initialized
	 * @throws - IllegalArgumentException if the given element is not RSA element
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException, UnInitializedException{
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		// gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement(); 
		
		//calls for the native function
		long result = computeRSA(tpPtr, elementP); 
		
		//creates and initializes CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/**
	 * Inverts the RSA permutation on the given element 
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws UnInitializedException 
	 * @throws - IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException, UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		//in case that the initialization was with public key and no private key - can't do the invert and returns null
		if (privKey == null && pubKey!=null)
			return null;
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		//gets the pointer for the native object
		long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//calls for the native function
		long result = invertRSA(tpPtr, elementP); 
		
		//creates and initialize CryptoPpRSAElement with the result
		CryptoPpRSAElement returnEl = new CryptoPpRSAElement(result);
		
		return returnEl; // returns the result TPElement
	}
	
	/** 
	 * Checks if the given element is valid for this RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * There are three possible validity values: 
	 * VALID (it is an element)
	 * NOT_VALID (it is not an element)
	 * DON’T_KNOW (there is not enough information to check if it is an element or not)  
	 * @throws UnInitializedException if this object is not initialized
	 * @throws - IllegalArgumentException if the given element is invalid for this RSA permutation
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException, UnInitializedException{
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		
		if (!(tpEl instanceof CryptoPpRSAElement)){
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		TPElValidity validity = null;
		long value = ((CryptoPpRSAElement)tpEl).getPointerToElement();
		
		//if the trapdoor permutation is unknown - returns DONT_KNOW 
		if (modN == null) {
			validity = TPElValidity.DONT_KNOW;
		
		//if the value is valid (between 1 to (mod n) - 1) returns VALID 
		} else if(checkRSAValidity(value, tpPtr)) {
			
			validity = TPElValidity.VALID;
		//if the value is invalid returns NOT_VALID 
		} else {
			validity = TPElValidity.NOT_VALID;
		}		
		
		//returns the correct TPElValidity
		return validity;
	}

	/** 
	 * creates a random CryptoPpRSAElement
	 * @return TPElement - the created random element 
	 * @throws UnInitializedException if this object is not initialized
	 */
	public TPElement getRandomTPElement() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return new CryptoPpRSAElement(modN);
	}
	
	/**
	 * deletes the native RSA object
	 */
	protected void finalize() throws Throwable {
		
		//deletes from the dll the dynamic allocation of the RSA permutation.
		deleteRSA(tpPtr);
		
		super.finalize();
	}
	
	//loads the dll
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }
	
	
	
}