package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import edu.biu.scapi.primitives.trapdoorPermutation.RSAElement;
import edu.biu.scapi.primitives.trapdoorPermutation.RabinKeyGenParameterSpec;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;

/**
 * 
 * This class tests the performance and correctness of the Rabin algorithm.
 * 
 * Since there is no test vector for Rabin computation, we use
 * the compute&invert mechanism to verify that the result of invert on compute return the original input.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public abstract class RabinTest extends TrapdoorPermutationTest {
	/**
	 * Sets the given TrapdoorPermutation object, adds data for the test vectors.
	 */
	public RabinTest(TrapdoorPermutation tp) {
		super(tp);

		
		//get RabinKeyGenParameterSpec to init the tp 
		RabinKeyGenParameterSpec spec = new RabinKeyGenParameterSpec(1024);
		
		
		//get RabinKeyGenParameterSpec to init the tp 
		RabinKeyGenParameterSpec spec1 = new RabinKeyGenParameterSpec(2048);
		
		//get RabinKeyGenParameterSpec to init the tp 
		RabinKeyGenParameterSpec spec2 = new RabinKeyGenParameterSpec(4096);
		

		//adds the algorithmParameterSpec to the compute-invert test vector. A random elements and keys will be chosen and tested.
		addDataInvertCompute(null, spec);
		addDataInvertCompute(null, spec1);
		addDataInvertCompute(null, spec2);
	}
	
	/**
	 * Test the case that the given argument is not a Rabin element. 
	 * @param file the output file
	 */
	protected void wrongArgumentType(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//init the tp
			tp.init(testDataInvertCompute.get(0).spec);
			//creates a RSA element
			RSAElement element = new RSAElement(tp.getModulus());
			
			//calls the compute function and send the RSA object
			tp.compute(element);
			
		//the expected result of this test is IllegalArgumentException
		} catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		} catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Wrong argument type,Wrong behavior,,," + testResult);
	}
	
	/**
	 * Test the case that the given key is not a Rabin key. 
	 * @param file the output file
	 */
	protected void wrongKeyType(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets RSA public and private keys
			RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(1024, new BigInteger("3"));
			KeyPairGenerator kpr;
			kpr = KeyPairGenerator.getInstance("RSA");
			kpr.initialize(((RSAKeyGenParameterSpec) spec).getKeysize());
			KeyPair pair = kpr.generateKeyPair();
			PublicKey publicKey = pair.getPublic();
			PrivateKey privateKey = pair.getPrivate();
			
			//init the Rabin object with RSA keys
			tp.init(publicKey, privateKey);
			
			//the expected result of this test is InvalidKeyException
		} catch(InvalidKeyException e){
			testResult = "Success: The expected exception \"InvalidKeyException\" was thrown";
		//any other exception is a failure
		} catch(Exception e){}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Wrong key type,Wrong behavior,,," + testResult);
		
	}

}
