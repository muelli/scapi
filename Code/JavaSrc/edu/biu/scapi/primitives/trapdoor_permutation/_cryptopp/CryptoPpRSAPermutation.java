/**
 * 
 */
package edu.biu.scapi.primitives.trapdoor_permutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import edu.biu.scapi.primitives.trapdoor_permutation.RSAPermutation;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoor_permutation.TrapdoorPermutationAbs;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.TPElement;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.cryptopp.CryptoPpRSAElement;

/** 
 */
public final class CryptoPpRSAPermutation extends TrapdoorPermutationAbs implements RSAPermutation {

	private long tpPtr;
	
	private native long initRSAWithNED(byte[] modulus, byte[] pubExponent, byte[] privExponent);
	private native long initRSAWithCrt(byte[] modulus, byte[] pubExponent, byte[] privExponent, 
									   byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] crt);
	private native long initRSAWithNE(byte[] modulus, byte[] pubExponent);
	private native long initRSAWithNumBitsAndE(int numBits, byte[] pubExponent);
	
	private native String loadRSAName(long ptr);
	private native byte[] getRSAModulus(long ptr);
	private native boolean checkRSAValidity(long value, long ptr);
	
	private native long computeRSA(long tpr, long x);
	private native long invertRSA(long ptr, long y);
	
	private native void deleteRSA(long ptr);
	

	/** 
	 * No such implementation for RSA permutation. throws IllegalAccessException.
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @param params
	 * @throws IllegalAccessException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws IllegalAccessException {
		
		throw new IllegalAccessException("no such RSA initialization");

	}
	
	/** 
	 * Initializes this trapdoor permutation with n, e, d
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		//call the parent init
		super.init(publicKey, privateKey);
		
		if (publicKey instanceof RSAPublicKey && privateKey instanceof RSAPrivateKey) {
			
			/* get the values of modulus (N), pubExponent (e), privExponent (d)*/
			BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
			BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
			modN = ((RSAKey) publicKey).getModulus();
			
			//if private key is CRT private key
			if (privateKey instanceof RSAPrivateCrtKey)
			{
				//get all the inputs
				RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
				BigInteger p = key.getPrimeP();
				BigInteger q = key.getPrimeQ();
				BigInteger dp = key.getPrimeExponentP();
				BigInteger dq = key.getPrimeExponentQ();
				BigInteger crt = key.getCrtCoefficient();
				
				//initialize the native object
				tpPtr = initRSAWithCrt(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
						p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
				
			//if private key is key with N, e, d
			} else {
				
				//init the native object with the RSA parameters - n, e, d
				tpPtr = initRSAWithNED(modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
			}
			
			beInit = true;
		} else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
	}

	/** 
	 * Initializes this trapdoor permutation with n, e
	 * @param publicKey - public key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException {
			
		//call the parent init
		super.init(publicKey);
		if (publicKey instanceof RSAPublicKey) {
			
			RSAPublicKey pub = (RSAPublicKey) publicKey;
			BigInteger pubExponent = pub.getPublicExponent();
			modN = pub.getModulus();
			
			//init the native object with the RSA parameters - n, e
			tpPtr = initRSAWithNE(modN.toByteArray(), pubExponent.toByteArray());

			beInit = true;
		} else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
	}
	
	/** 
	 * Initializes this trapdoor permutation with numBits and public exponent
	 * @param params
	 * @throws IllegalAccessException 
	 */
	public void init(AlgorithmParameterSpec params) throws IllegalArgumentException  {
		
		if (params instanceof RSAKeyGenParameterSpec) {
			
			//call the parent init
			super.init(params);
		
			//get the numBits and public exponent
			int numBits = ((RSAKeyGenParameterSpec) params).getKeysize();
			BigInteger pubExp = ((RSAKeyGenParameterSpec) params).getPublicExponent();

			//init the native object 
			tpPtr = initRSAWithNumBitsAndE(numBits, pubExp.toByteArray());
			//set the mod
			modN = new BigInteger(getRSAModulus(tpPtr));
			
			beInit = true;
		} else {
			throw new IllegalArgumentException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}

	}
	
	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName() {
		
		return loadRSAName(tpPtr);
	}

	/** 
	 * Compute the operation of this trapdoor permutation on the TPElement that was accepted
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws - IllegalArgumentException
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{
		CryptoPpRSAElement returnEl = null;
		
		if (tpEl instanceof CryptoPpRSAElement)
		{
			// get the pointer for the native object
			long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement(); 
			
			//call for the native function
			long result = computeRSA(tpPtr, elementP); 
			
			//create and initialize RSAElement with the result
			returnEl = new CryptoPpRSAElement(result);
		} else {
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		return returnEl; // return the result TPElement
	}
	
	/**
	 * Invert the operation of this trapdoor permutation on the element that was accepted
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws - IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException {
		
		//in case that the initialization was just with public key - can't do the invert and return null
		if (privKey == null && pubKey!=null)
			return null;
		CryptoPpRSAElement returnEl = null;
		
		if (tpEl instanceof CryptoPpRSAElement)
		{
			 // get the pointer for the native object
			long elementP = ((CryptoPpRSAElement)tpEl).getPointerToElement();
			
			//call for the native function
			long result = invertRSA(tpPtr, elementP); 
			
			//create and initialize RSAElement with the result
			returnEl = new CryptoPpRSAElement(result);
		} else {
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		return returnEl; // return the result TPElement
	}
	
	/** 
	 * Check if the given element is valid to RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * @throws - IllegalArgumentException
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException{
		TPElValidity validity = null;
		
		if (tpEl instanceof CryptoPpRSAElement){
			
			long value = ((CryptoPpRSAElement)tpEl).getPointerToElement();
			
			//if the trapdoor permutation is unknown - return DONT_KNOW 
			if (modN == null) {
				validity = TPElValidity.DONT_KNOW;
			
			//if the value is valid (between 1 to (mod n) - 1) return VALID 
			} else if(checkRSAValidity(value, tpPtr)) {
				
				validity = TPElValidity.VALID;
			//if the value is invalid return NOT_VALID 
			} else {
				validity = TPElValidity.NOT_VALID;
			}		
		}else {
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		//return the correct TPElValidity
		return validity;
	}

	/** 
	 * create random CryptoPpRSAElement
	 * @return TPElement - the random element 
	 */
	public TPElement getRandomTPElement() {
		return new CryptoPpRSAElement(modN);
	}
	
	/**
	 * delete the native RSA object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the trapdoor.
		deleteRSA(tpPtr);
		
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("JavaInterface");
	 }
	
	
	
}