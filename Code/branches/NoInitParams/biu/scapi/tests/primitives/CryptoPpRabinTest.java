package edu.biu.scapi.tests.primitives;

import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;

/**
 * Concrete class of TrapdoorPermutationTest for crypto++ implementation of Rabin.
 * 
 * Unlike other families, creation of a TPElment differs for each library implementation. 
 * Thus there is a test class for each concrete trapdoor implementation, which contains one 
 * function of creating elements of the concrete implementation type.
 * 
 * Currently this class adds no functionality to the base class. However, if a vector test for his algorithm will 
 * be supplied we will need to create and element in different ways thru the specific library classes.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CryptoPpRabinTest extends RabinTest {
	
	/**
	 * Sets the given Rabin permutation and calls super implementation which initializes the test vectors of RSA
	 */
	public CryptoPpRabinTest(TrapdoorPermutation tp) {
		super(tp);
		
	}
	
}
