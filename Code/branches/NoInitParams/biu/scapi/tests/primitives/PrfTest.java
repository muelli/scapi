package edu.biu.scapi.tests.primitives;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prf.PseudorandomFunction;
import edu.biu.scapi.tests.Test;

/**
 * Tests the prf objects. <p>
 * This class has some goals:
 * The main goal is to check that prf classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class PrfTest extends Test {
	
	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	PseudorandomFunction prf;//the underlying prf
	String provider = null; //the underlying prf provider name 
	
	/**
	 * Sets the tested prf and its provider
	 */
	public PrfTest(PseudorandomFunction prf) {
		
		this.prf = prf;
		
		//the class name contains the path, which contains the provider name
		//we save the provider name for further usage
		if (prf.getClass().toString().split("\\.")[5].equals("bc")){
			provider = "BC";
		} else {
			provider = "Scapi";
		}
		
	}
	
	/**
	 * 
	 * Adds one test data to the java vector testDataVector.
	 * @param input the tested input
	 * @param output the expected output. The vector test will pass if the outcome of the computation will yield the byte array output
	 * @param key the related secret key
	 */
	protected void addData(byte[] input, byte[] output, byte[] key){
		//adds the data to the test vector
		TestData testData = new TestData(input, output, key);
		
		testDataVector.add(testData);
		
	}
	
	/** 
	 * A general test. This can be done since the derived classes filled the vector of vector tests.
	 * each data in the vector is tested and the test output is written to the output file
	 * @param file the output file
	 */
	public void testVector(PrintWriter file) {

		byte[] out;  
		
		//goes over the test vector and tests each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//sets the output size to be the same as the expected result length.
			out = new byte[(testDataVector.get(i).output).length];
			
			//tests the test vector by calling computeAndCompare function. 
			computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output, testDataVector.get(i).key, file);
		}
		
		//some derived classes (like prp) have more tests, which are done in the test function
		test(file);
	}
	
	
	/**
	 * Computes the result of the prf and compares it with the expected output.
	 * Writes the result t othe given output file
	 * @param out byte array to fill the output of the prf function
	 * @param in the input to the prf function
	 * @param outBytes the expected output on the input in
	 * @param key the key for the prf
	 * @param file the output file
	 */

	protected void computeAndCompare(byte[] out, byte[] in, byte[] outBytes, byte[] key, PrintWriter file) {
		
		//creates a SecretKey object out of the byte array key.
		SecretKey secretKey = new SecretKeySpec(key, "");
		try {
			//initializes the prf with the new secret key
			prf.init(secretKey);
		
			//computes the function
			prf.computeBlock(in, 0, in.length, out, 0, out.length);
		} catch (IllegalBlockSizeException e) {
			//shouldn't be called since the offsets and lengths are in the range
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (UnInitializedException e) {
			//shouldn't be called since the object is initialized
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (InvalidKeyException e) {
			//shouldn't be called since the vector test is known and correct
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		//if out is equal to the outbytes than result is sets to true
		boolean result =  Arrays.equals(out,outBytes);
		
		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		OutputStream inString = new ByteArrayOutputStream();
		OutputStream outString = new ByteArrayOutputStream();
		OutputStream outExString = new ByteArrayOutputStream();
		String input = null;
		String output = null;
		String expected = null;
		try {
			Hex.encode(in, inString);
			input = inString.toString();
			if (input.length()>100){
				input = input.substring(0,99)+"...";
			}
			Hex.encode(out, outString);
			output = outString.toString();
			if (output.length()>100){
				output = output.substring(0,99)+"...";
				
			}
			Hex.encode(outBytes, outExString);
			expected = outExString.toString();
			if (expected.length()>100){
				expected = expected.substring(0,99)+"...";
				
			}
		} catch (IOException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//writes the result to a string
		String testResult = null;
		if (result){
			testResult = "Success: output is as expected";
		} else {
			testResult = "Failure: output is different from the expected " + expected;
		}
		//writes the test results to the given output file
		file.println(prf.getAlgorithmName() + "," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);
		
	}
	
	/**
	 * A test that any derive class can implement to add its own required tests
	 * @param file the output file
	 */
	protected void test(PrintWriter file){
	}

	/**
	 * Runs all the required wrong behavior tests for prf. Each test can be either implemented in the derived hash test class
	 * or in this abstract class.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions
		unInited(file); //case that a function is called while the object is not initialized
		wrongKeySize(file); //case that the given key has wrong size
		wrongOffset(file); //case that the given offset is not in the range
		wrongLength(file); // case that the given length is wrong
		badCasting(file); //case that the input was casted badly
		
	}
	
	/**
	 * Tests the case that the given initialization key has wrong size.
	 * @param the output file
	 */
	protected void wrongKeySize(PrintWriter file) {
		//the general prf has no key limitation so the test result is true
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong key size,Wrong behavior,,,Success: This Algorithm has no key size limitations");
	}

	/**
	 * Tests the case that a function is called while the object is not initialized.
	 * the expected result is to throw UnInitializedException
	 * @param the output file
	 */
	protected void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			byte[] out = null; 
			byte[] input = getData();
			//computes the function
			prf.computeBlock(input, 0, input.length, out, 0, 0);
			
		//the right result of this test is UnInitializedException
		} catch (UnInitializedException e) {
			testResult = "Success: The expected exception \"UnInitializedException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"UnInitializedException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",unInited,Wrong behavior,,," + testResult);	
	}

	/** 
	 * Tests the case that a compute function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	protected void wrongOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(testDataVector.get(0).key, "");
			
			//init the prf with the new secret key
			prf.init(secretKey);
			
			byte[] out = new byte[(testDataVector.get(0).output).length]; // create an out array
			byte[] input = getData(); //get the input
			//computes the function with offsets out of the arrays length
			prf.computeBlock(input, input.length+1, input.length, out, out.length+1, out.length);
			
		//the right result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e) {
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong offset,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that a compute function is called with a wrong length.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	protected void wrongLength(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(testDataVector.get(0).key, "");
			
			//init the prf with the new secret key
			prf.init(secretKey);
			
			byte[] out = new byte[(testDataVector.get(0).output).length]; // create an out array
			byte [] input = getData();  //get the input
			//computes the function with lengths bigger than the arrays size
			prf.computeBlock(input, 0, input.length+2, out, 0, out.length+2);
			
		//the right result of this test is ArrayIndexOutOfBoundsException or IllegalBlockSizeException
		} catch (ArrayIndexOutOfBoundsException e) {
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		} catch (IllegalBlockSizeException e) {
			testResult = "Success: The expected exception \"IllegalBlockSizeException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exceptions was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Wrong length,Wrong behavior,,," + testResult);
	}
	
	/** 
	 * Tests the case that the given argument is not match the argument type
	 * the expected result is to throw ClassCastException
	 * @param the output file
	 */
	private void badCasting(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//init the prf with the public key with casting to secretKey
			prf.init((SecretKey) new RSAPublicKeySpec(null, null));
			
		//the right result of this test is ClassCastException
		} catch (ClassCastException e) {
			testResult = "Success: The expected exception \"ClassCastException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ClassCastException\" was thrown";
		}
		
		//writes the result to the file
		file.println(prf.getAlgorithmName() + "," + provider + ",Bad casting,Wrong behavior,,," + testResult);
		
	}
	
	/**
	 * Some wrong behavior functions need input for the calculations. 
	 * This function implements one option for data, and every derived class can implement it differently.
	 * @return the data for wrongBehavior tests
	 */
	protected byte[] getData() {
		return testDataVector.get(0).input;
	}
	
	/**
	 * Some wrong behavior functions need key for the calculations. 
	 * This function implements one option for key, and every derived class can implement it differently.
	 * @return the key for wrongBehavior tests
	 */
	protected byte[] getKey() {
		return testDataVector.get(0).key;
	}
	
	/**
	 * Nested TestData class, which is the data for the test vector.
	 * It contains the input, expected output and the key
	 *
	 */
	class TestData{
		byte[] input;
		byte[] output;
		byte[] key;
		
		/**
		 * Sets the data
		 */
		public TestData(byte[] input, byte[] output, byte[] key) {
			this.input = input;
			this.output = output;
			this.key = key;
		}
		
	}
	
}