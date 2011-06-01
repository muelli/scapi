/**
 * 
 */
package edu.biu.scapi.primitives.trapdoor_permutation;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.RSAElement;
import edu.biu.scapi.primitives.trapdoor_permutation.TPElement.TPElement;


public final class RSAPermutationImpl extends TrapdoorPermutationAbs implements RSAPermutation {
	
	
	/** 
	 * Initializes this trapdoor permutation with keys and params and convert the parameters to the bc parameters
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
	 * Initializes this trapdoor permutation with keys and convert the parameters to the bc parameters
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		
		if (publicKey instanceof RSAPublicKey && privateKey instanceof RSAPrivateKey) {
			//init this trapdoor permutation
			super.init(publicKey, privateKey);
			
			RSAPublicKey pub = (RSAPublicKey) pubKey;
			modN = pub.getModulus();
				
			beInit = true;
			
		} else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
	}
	
	/** 
	 * Initializes this trapdoor permutation just with public key and convert the parameters to the bc parameters
	 * @param publicKey - public key
	 * @throws InvalidKeyException 
	 */
	public void init(PublicKey publicKey) throws InvalidKeyException {
		
		if (publicKey instanceof RSAPublicKey) {
			
			//init this trapdoor permutation
			super.init(publicKey);
			
			RSAPublicKey pub = (RSAPublicKey) pubKey;
			modN = pub.getModulus();
			
			beInit = true;
			
		} else {
			throw new InvalidKeyException("Key type doesn't match the trapdoor permutation type");
		}
	}
	
	/** 
	 * Initializes this trapdoor permutation with keys and params and convert the parameters to the bc parameters
	 * @param publicKey - public key
	 * @param privateKey - private key
	 * @param params
	 * @throws IllegalArgumentException 
	 */
	public void init(AlgorithmParameterSpec params) throws IllegalArgumentException {
		
		
		if(params instanceof RSAKeyGenParameterSpec)
		{
			try {
				//call the parent init
				super.init(params);
				
				/*generate public and private keys */
				KeyPairGenerator kpr;
				kpr = KeyPairGenerator.getInstance("RSA");
				kpr.initialize(((RSAKeyGenParameterSpec) params).getKeysize());
				KeyPair pair = kpr.generateKeyPair();
				PublicKey publicKey = pair.getPublic();
				PrivateKey privateKey = pair.getPrivate();
				
				//init the trapdoor permutation with this keys
				init(publicKey, privateKey);
				
				beInit = true;
			} catch (NoSuchAlgorithmException e) {
				Logging.getLogger().log(Level.WARNING, e.toString());
			} catch (InvalidKeyException e) {
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		} else {
			throw new IllegalArgumentException("AlgorithmParameterSpec type doesn't match the trapdoor permutation");
		}
	}
	
	/** 
	 * @return the algorithm name
	 */
	public String getAlgorithmName() {
		return "RSA";
	}
	
	/** 
	 * Compute the operation of RSA permutation on the TPElement that was accepted
	 * @param tpEl - the input for the computation
	 * @return - the result TPElement
	 * @throw IllegalArgumentException
	 */
	public TPElement compute(TPElement tpEl) throws IllegalArgumentException{
		
		RSAElement returnEl = null;
		
		if (tpEl instanceof RSAElement) {
			// get the value of the element 
			BigInteger element = ((RSAElement)tpEl).getElement();
			//compute - calculate (element^e)modN
			BigInteger result = element.modPow(
            		((RSAPublicKey)pubKey).getPublicExponent(), ((RSAPublicKey)pubKey).getModulus());
			// build the return element
			returnEl = new RSAElement(modN, result);
			
		} else {
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}
			
		//return the result of the computation
		return returnEl;
	}

	/** 
	 * Invert the operation of RSA permutation on the TPElement that was accepted
	 * @param tpEl - the input to invert
	 * @return - the result 
	 * @throws IllegalArgumentException
	 */
	public TPElement invert(TPElement tpEl)  throws IllegalArgumentException{
		
		//in case that the initialization was just with public key - can't do the invert and return null
		if (privKey == null && pubKey!=null)
			return null;
		
		RSAElement returnEl = null;
		
		if (tpEl instanceof RSAElement) {
			// get the value of the element 
			BigInteger element = ((RSAElement)tpEl).getElement();
			//invert 
			BigInteger result = doInvert(element);
			//build the return element
			returnEl = new RSAElement(modN, result);
		} else {
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}
		
		//return the result
		return returnEl;
	}

	/**
	 * This function invert the permutation according to the key.
	 * If the key is CRT key - invert using the Chinese Remainder Theorem.
	 * Else - invert using d, modN.
	 * @param input - The element to invert
	 * @return BigInteger - the result
	 */
	public BigInteger doInvert(BigInteger input)
    {
		if (privKey instanceof RSAPrivateCrtKey) //invert with CRT parameters
        {
            // we have the extra factors, use the Chinese Remainder Theorem 
            RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey)privKey;

            BigInteger p = crtKey.getPrimeP();
            BigInteger q = crtKey.getPrimeQ();
            BigInteger dP = crtKey.getPrimeExponentP();
            BigInteger dQ = crtKey.getPrimeExponentQ();
            BigInteger qInv = crtKey.getCrtCoefficient();

            BigInteger mP, mQ, h, m;

            // mP = ((input mod p) ^ dP)) mod p
            mP = (input.remainder(p)).modPow(dP, p);

            // mQ = ((input mod q) ^ dQ)) mod q
            mQ = (input.remainder(q)).modPow(dQ, q);

            // h = qInv * (mP - mQ) mod p
            h = mP.subtract(mQ);
            h = h.multiply(qInv);
            h = h.mod(p);               // mod (in Java) returns the positive residual

            // m = h * q + mQ
            m = h.multiply(q);
            m = m.add(mQ);

            return m;
        }
        else //invert using d, modN
        {
            return input.modPow(
            		((RSAPrivateKey)privKey).getPrivateExponent(), ((RSAPrivateKey)pubKey).getModulus());
        }
    }
	
	
	/** 
	 * Check if the given element is valid to RSA permutation
	 * @param tpEl - the element to check
	 * @return TPElValidity - enum number that indicate the validation of the element 
	 * @throws IllegalArgumentException
	 */
	public TPElValidity isElement(TPElement tpEl) throws IllegalArgumentException{
		TPElValidity validity = null;
		
		if (tpEl instanceof RSAElement){
			
			BigInteger value = ((RSAElement)tpEl).getElement();
			
			//if mod n is unknown - return DONT_KNOW 
			if (modN==null) {
				validity = TPElValidity.DONT_KNOW;
				
			//if the value is valid (between 1 to (mod n) - 1) return VALID 
			} else if(((value.compareTo(BigInteger.ZERO))>0) && (value.compareTo(modN)<0)) {
				
				validity = TPElValidity.VALID;
			//if the value is invalid return NOT_VALID 
			} else {
				validity = TPElValidity.NOT_VALID;
			}		
		}else {
			throw new IllegalArgumentException("trapdoor element doesn't match the trapdoor permutation");
		}
		//return the correct TPElValidity
		return validity;
	}

	/** 
	 * create random BcRSAElement 
	 * @return TPElement - BcRSAElement
	 */
	public TPElement getRandomTPElement() {
		
		return new RSAElement(modN);
	}


	

	
}