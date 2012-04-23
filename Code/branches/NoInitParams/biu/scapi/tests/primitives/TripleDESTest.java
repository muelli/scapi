package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.prf.TripleDES;

/**
 * This class tests the performance and correctness of any implemented TripleDES algorithm.
 * There is no known vector test that for triple DES without some kind of mode of operation. Thus, we use
 * the compute&invert mechanism to verify that the result of invert on compute return the original input.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class TripleDESTest extends PrpTest {


	/**
	 * 
	 */
	public TripleDESTest(TripleDES tripleDES) {
		
		super(tripleDES);
		
		
		byte[] input = {1, 0, 1, 0, 0, 0, 0, 0};
		byte[] key = {1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0};
		
		byte[] input2 = {1, 3, 8, 9, 9, 10, 11, 12};
		byte[] key2 = {1, 0, 12, 13, 14, 15, 15, 15, 4, 2, 1, 7, 8, 2, 2, 0};
		
		byte[] input3 = {1, 0, 1, 0, 23, 22, 4, 5};
		byte[] key3 = {1, 0, 1, 0, 0, 24, 2, 4, 1, 9, 1, 6, 5, 0, 0, 0};
		
		
		//Fills the vector of compute and invert of the base class
		addDataInvertCompute(input,	key);

		addDataInvertCompute(input2, key2);
		
		addDataInvertCompute(input3, key3);
		
	}
	
	/**
	 * Some wrong behavior functions need an input for the calculations. 
	 * This function overrides the super implementation because the super returns the input from the test vector "testDataVector", which is empty in this object.
	 * Thus, returns the input from the test vector "testDataInvertcompute".
	 * @return the data for wrongBehavior tests 
	 */
	protected byte[] getData() {
		return testDataInvertcompute.get(0).input;
	}
	
	/**
	 * Some wrong behavior functions need a key for the calculations. 
	 * This function overrides the super implementation because the super returns the key from the test vector "testDataVector", which is empty in this object.
	 * Thus, returns the key from the test vector "testDataInvertcompute".
	 * @return the key for wrongBehavior tests
	 */
	protected byte[] getKey() {
		return testDataInvertcompute.get(0).key;
	}
	
	/**
	 * Tests the case that the given initialization key has wrong size.
	 * The expected output is InvalidKeyException
	 * @param the output file
	 */
	protected void wrongKeySize(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405"), "");
			
			//init the prf with the new secret key
			prf.setKey(secretKey);
		
		//the right result of this test is InvalidKeyException
		} catch (InvalidKeyException e) {
			testResult = "Success: The expected exception \"InvalidKeyException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"InvalidKeyException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong key size,Wrong behavior,,," + testResult);
		
	}
}