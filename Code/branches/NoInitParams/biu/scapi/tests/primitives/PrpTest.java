package edu.biu.scapi.tests.primitives;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;

/**
 * Tests the prp objects. <p>
 * This class extends the abstract class prfTest in order to test the prp objects. 
 * This class adds the functionality of inverting a computed value and checking that the result is
 * equal to the original input value. This could not be part of the base class PrfTest since a PRF is not
 * invertible. However, every PRP is invertible. This functionality is really helpful if a derived PRP does not
 * have a known vector test.
 * This class does all the testing of compute and invert and it is the responsibility of the derived class
 * to fill the vector of data to check. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class PrpTest extends PrfTest {
	
	Vector<TestData> testDataInvertcompute = new Vector<TestData>();//holds the tests to check that the input returns to its original value after compute and invert in each TestData object
	
	public PrpTest(PseudorandomPermutation prp) {
		//sets the tested object
		super(prp);
	}

	/**
	 * 	 * Adds one test with input and key to the java vector testDataInvertcompute.
	 * @param input the tested input
	 * @param key the related secret key
	 */
	protected void addDataInvertCompute(byte[] input, byte[] key){
		//create an instance of testData and add it to the test vector
		TestData testData = new TestData(input, null, key);
		
		testDataInvertcompute.add(testData);
		
	}
	
	/**
	 * Adds prp tests to the basic prf tests
	 * @param file the output file
	 */
	protected void test(PrintWriter file){
		//tests invert on computed value
		testComputeInvertVector(file);
	}
	
	/**
	 * Validates that compute and invert on the result returns to the original input.
	 * @param file the output file
	 */
	private void testComputeInvertVector(PrintWriter file) {

		//goes over the test vector and tests each data.
		for(int i=0; i<testDataInvertcompute.size();i++){
			
			//tests the test vector by calling computeAndInvertCompare function. 
			computeAndInvertCompare(testDataInvertcompute.get(i).input, testDataInvertcompute.get(i).key, file);
		}
		
	}
	
	/**
	 * Compute the prp operation on the input, inverts the result and check if the output is equal to the original input.
	 * @param input the value to compute
	 * @param key the key of the prp
	 * @param file the output file
	 */
	private void computeAndInvertCompare(byte[] input, byte[] key, PrintWriter file) {

		//creates a SecretKey object out of the byte array key.
		SecretKey secretKey = new SecretKeySpec(key, "");

		//create two arrays for the results
		//the out length should be equal to the length of the input array since this is a prp
		byte[] out = new byte[input.length];
		byte[] computedInput = new byte[input.length];
		
		try {
			//init the prp with the new secret key
			prf.setKey(secretKey);
		
			//computes the function to get the output array.
			prf.computeBlock(input, 0, input.length, out, 0, out.length);
		
			//retrieve the input by inverting the computed result
			((PseudorandomPermutation)prf).invertBlock(out, 0, computedInput, 0, input.length);
		} catch (IllegalBlockSizeException e) {
			// should not happen since the offsets and length are correct
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (InvalidKeyException e) {
			//shouldn't happen since the key in the test vector is known and correct
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//gets the results. if the output is equal to the expected, this is a success
		String testResult = null;
		if (Arrays.equals(input,computedInput)){
			testResult = "Success: output is as the input";
		} else {
			testResult = "Failure: output is different from the input";
		}
		
		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		OutputStream inString = new ByteArrayOutputStream();
		OutputStream outString = new ByteArrayOutputStream();
		String in = null;
		String output = null;
		try {
			Hex.encode(input, inString);
			in = inString.toString();
			if (in.length()>100){
				in = in.substring(0,99)+"...";
			}
			Hex.encode(out, outString);
			output = outString.toString();
			if (output.length()>100){
				output = output.substring(0,99)+"...";
				
			}
		} catch (IOException e) {
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//writes the test results to the given output file
		file.println(prf.getAlgorithmName() + "," + provider + ",Compute and invert compare,Test vector," + in + "," + output + ","+testResult);
	}
	
	/**
	 * Runs all the required wrong behavior tests for prf. Each test can be either implemented in the derived hash test class
	 * or in this abstract class.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions of prf and adds the wrong behavior of prp
		super.wrongBehavior(file);
		wrongInvertOffset(file); //case that the given offset for the invert function is not in the range
		wrongInvertLength(file); //case that the given length for the invert function is not in the range
		
	}
	
	/** 
	 * Tests the case that a invert function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongInvertOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(testDataVector.get(0).key, "");
			
			//init the prf with the new secret key
			prf.setKey(secretKey);
			
			byte[] out = new byte[(testDataVector.get(0).output).length];
			//inverts the function with offsets out of the arrays length
			((PseudorandomPermutation)prf).invertBlock(testDataVector.get(0).input, testDataVector.get(0).input.length+2, out, testDataVector.get(0).input.length+2, testDataVector.get(0).input.length);
			
		//the right result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e) {
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong invert offset,Wrong behavior,,,"+testResult);	
	}

	/** 
	 * Tests the case that a invert function is called with a wrong length.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongInvertLength(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(testDataVector.get(0).key, "");
			
			//init the prf with the new secret key
			prf.setKey(secretKey);
			
			byte[] out = new byte[(testDataVector.get(0).output).length];
			//inverts the function with lengths out of the arrays length
			((PseudorandomPermutation)prf).invertBlock(testDataVector.get(0).input, 0, out, 0, testDataVector.get(0).input.length+2);
		
		//the right result of this test is ArrayIndexOutOfBoundsException or IllegalBlockSizeException
		} catch (ArrayIndexOutOfBoundsException e) {
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		} catch (IllegalBlockSizeException e) {
			testResult = "Success: The expected exception \"IllegalBlockSizeException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong invert length,Wrong behavior,,,"+testResult);
		
	}

	
}
