package edu.biu.scapi.tests.primitives;

import java.math.BigInteger;

import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;
import edu.biu.scapi.primitives.trapdoorPermutation.cryptopp.CryptoPpRSAElement;

/**
 * Concrete class of TrapdoorPermutationTest for Crypto++ implementation of RSA.
 * 
 * Unlike other families, creation of a TPElment differs for each library implementation. 
 * Thus there is a test class for each concrete trapdoor implementation, which contains one 
 * function of creating elements of the concrete implementation type.
 * 
 * This class creates an element of type CryptoPpRSAElement.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CryptoPpRSATest extends RSATest{
	
		
	/**
	 * Sets the given RSA permutation and calls super implementation which initializes the test vectors of RSA
	 */
	public CryptoPpRSATest(TrapdoorPermutation tp) {
		super(tp);
	}
	
	/**
	 * Creates CryptoPpRSAElement with the given value and returns it.
	 * @return TPElement the created CryptoPpRSAElement
	 */
	protected TPElement createElement(BigInteger modulus, BigInteger value){
		TPElement element = new CryptoPpRSAElement(modulus, value);
		return element;
	}

	
}
