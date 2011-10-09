/**
 * 
 */
package edu.biu.scapi.primitives.trapdoor_permutation.cryptopp;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.trapdoor_permutation.RabinKeyGenParameterSpec;
import edu.biu.scapi.primitives.trapdoor_permutation.RabinPermutation;
import edu.biu.scapi.primitives.trapdoor_permutation.RabinPrivateKey;
import edu.biu.scapi.primitives.trapdoor_permutation.RabinPublicKey;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElValidity;
import edu.biu.scapi.primitives.trapdoor_permutation.TrapdoorPermutationAbs;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.TPElement;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.cryptopp.CryptoPpRabinElement;

/** 
 * 
 */
public final class CryptoPpRabinPermutation extends TrapdoorPermutationAbs implements RabinPermutation {
	
	private long tpPtr;
	
	private native long initRabinAll(byte[] mod, byte[] r, byte[] s, byte[] p, byte[] q, byte[] u);
	private native long initRabinNRS(byte[] mod, byte[] r, byte[] s);
	private native long initRabinKeySize(int numBits);
	
	private native String loadRabinName(long ptr);
	private native byte[] getRabinModulus(long ptr);
	private native boolean checkRabinValidity(long value, long tpPtr);
	
	private native long computeRabin(long tpr, long x);
	private native long invertRabin(long ptr, long y);

	private native void deleteRabin(long ptr);
	
	

	/** 
	 * No such implementation for RSA permutation. throws IllegalAccessException.
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @param params
	 * @throws IllegalAccessException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey,
			AlgorithmParameterSpec params) throws IllegalAccessException {
		
		throw new IllegalAccessException("no such Rabin initialization");

	}
	
	/** 
	 * Initializes this trapdoor permutation with n, r, s, p, q, u
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
			
		//call the parent init
		super.init(publicKey, privateKey);
		
		if (publicKey instanceof RabinPublicKey && privateKey instanceof RabinPrivateKey) {
			
			RabinPublicKey pub = (RabinPublicKey)publicKey;
			RabinPrivateKey priv = (RabinPrivateKey)privateKey;
			
			//get all the parameters
			BigInteger r, s, p, q, u;
			modN = pub.getModulus();
			r = pub.getQuadraticResidueModPrime1();
			s = pub.getQuadraticResidueModPrime2();
			p = priv.getPrime1();
			q = priv.getPrime2();
			u = priv.getInversePModQ();
			
		
			//init the rabin native object
			tpPtr = initRabinAll(modN.toByteArray(), r.toByteArray(), s.toByteArray(), 
						 p.toByteArray(), q.toByteArray(), u.toByteArray());
			
			beInit = true;
		}  else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
			
	}

	/** 
	 * Initializes this trapdoor permutation with n, r, s
	 * @param publicKey - public key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException {
			
		//call the parent init
		super.init(publicKey);
		
		if (publicKey instanceof RabinPublicKey) {
			
			RabinPublicKey pub = (RabinPublicKey)publicKey;
			//get the n, r, s
			BigInteger r,s;
			modN = pub.getModulus();
			r = pub.getQuadraticResidueModPrime1();
			s = pub.getQuadraticResidueModPrime2();
			
			//init the rabin native object
			tpPtr = initRabinNRS(modN.toByteArray(), r.toByteArray(), s.toByteArray());
			
			beInit = true;
		} else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
	}
	
	/** 
	 * Initializes this trapdoor permutation with numKeyBits
	 * @param params
	 * @throws InvalidParameterSpecException 
	 */
	public void init(AlgorithmParameterSpec params) throws InvalidParameterSpecException {

		if (!(params instanceof RabinKeyGenParameterSpec)) {
			throw new InvalidParameterSpecException("AlgorithmParameterSpec type doesn't match the trapdoor permutation type");
		}
		//call the parent init
		super.init(params);
		
		//get the numBits and public exponent
		int numBits = ((RabinKeyGenParameterSpec) params).getKeySize();

		//init the rabin native object
		tpPtr = initRabinKeySize(numBits);
		
		//set the modN
		modN = new BigInteger(getRabinModulus(tpPtr));
		
		beInit = true;

	}
	
	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName() {
		
		return loadRabinName(tpPtr);
	}
	
	/** 
	 * Compute the operation of this trapdoor permutation on the TPElement that was accepted
	 * @param tpEl - the input for the computation
	 * @return - the result element
	 * @throws UnInitializedException 
	 * @throws - IllegalArgumentException
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException, UnInitializedException{
		CryptoPpRabinElement returnEl = null;
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		if (tpEl instanceof CryptoPpRabinElement)
		{
			// get the pointer for the native object
			long elementP = ((CryptoPpRabinElement)tpEl).getPointerToElement(); 
			
			//call for the native function
			long result = computeRabin(tpPtr, elementP); 
			
			//create and initialize RSAElement with the result
			returnEl = new CryptoPpRabinElement(result);
		} else {
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		return returnEl; // return the result TPElement
	}
	
	/** 
	 * Invert the operation of this trapdoor permutation on the element that was accepted
	 * @param tpEl - the input to invert
	 * @return - the result element
	 * @throws UnInitializedException 
	 * @throws - IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl) throws IllegalArgumentException, UnInitializedException{
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		//in case that the initialization was just with public key - can't do the invert and return null
		if (privKey == null && pubKey!=null)
			return null;
		CryptoPpRabinElement returnEl = null;
		
		if (tpEl instanceof CryptoPpRabinElement)
		{
			// get the pointer for the native object
			long elementP = ((CryptoPpRabinElement)tpEl).getPointerToElement(); 
			
			//call for the native function
			long result = invertRabin(tpPtr, elementP); 
			
			//create and initialize RSAElement with the result
			returnEl = new CryptoPpRabinElement(result);
		} else {
			throw new IllegalArgumentException("trapdoor element type doesn't match the trapdoor permutation type");
		}
		
		return returnEl; // return the result TPElement
	}

	
	/** 
	 * Check if the given element is valid to Rabin permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * @throws UnInitializedException 
	 * @throws - IllegalArgumentException
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException, UnInitializedException{
		TPElValidity validity = null;
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		if (tpEl instanceof CryptoPpRabinElement){
			
			long value = ((CryptoPpRabinElement)tpEl).getPointerToElement();
			
			//if the trapdoor permutation or p,q are unknown - return DONT_KNOW 
			if ((modN == null) || ((privKey == null) && (pubKey != null))) {
				validity = TPElValidity.DONT_KNOW;
				
			//if the value is valid (between 1 to (mod n) - 1 and has a square root mod (N)) - return VALID 
			} else if(checkRabinValidity(value, tpPtr)) {
				
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
	 * create random CryptoPpRabinElement.
	 * @return TPElement - CryptoPpRabinElement
	 * @throws UnInitializedException 
	 */
	public TPElement getRandomTPElement() throws UnInitializedException {
		if (!IsInitialized()){
			throw new UnInitializedException();
		}
		return new CryptoPpRabinElement(modN);
	}

	/**
	 * delete the native Rabin object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the trapdoor.
		deleteRabin(tpPtr);
		
		super.finalize();
	}
	
	 static {
	        System.loadLibrary("JavaInterface");
	 }
	
}