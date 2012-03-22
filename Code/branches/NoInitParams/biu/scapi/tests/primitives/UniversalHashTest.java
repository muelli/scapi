package edu.biu.scapi.tests.primitives;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.paddings.PaddingParameterSpec;
import edu.biu.scapi.primitives.universalHash.UniversalHash;
import edu.biu.scapi.tests.Test;

/**
 * Tests the univarsal hash objects. <p>
 * This class has some goals:
 * The main goal is to check that uh classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class UniversalHashTest extends Test {

	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	UniversalHash uh;//the underlying universal hash 
	String provider = null; //the provider of the underlying object
	
	/**
	 * Sets the tested hash and its provider
	 * @param uh the tested universal hash
	 */
	public UniversalHashTest(UniversalHash uh) {
		
		this.uh = uh;
		
		provider = "Scapi";
	}

	/**
	 * 
	 * Adds one test vector to the java vector testDataVector.
	 * @param input the tested input
	 * @param output the expected output. The vector test will pass if the outcome of the computation will yield the byte array output
	 * @param key the related secret key
	 */
	protected void addData(byte[] input, byte[] output, byte[] key, PaddingParameterSpec padding){
		
		TestData testData = new TestData(input, output, key, padding);
		
		testDataVector.add(testData);
		
	}
	
	/** 
	 * 
	 * A general test. This can be done since the derived classes filled the vector of vector tests.
	 * Each data in the vector is tested and the test output is written to the output file
	 * @param file the output file
	 */
	
	public void testVector(PrintWriter file) {

		byte[] out;  
		//goes over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//sets the output size to be the same as the expected result length.
			out = new byte[(testDataVector.get(i).output).length];
			
			//tests the test vector by calling computeAndCompare function.
			computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output, testDataVector.get(i).key,  testDataVector.get(i).padding, file);
		}
	}
	
	
	/**
	 * Computes the result of the uh and compares it with the expected output. 
	 * @param out byte array to fill the output of the prf function
	 * @param in the input to the uh function
	 * @param outBytes the expected output on the input in
	 * @param key the key for the hash
	 * @param padding 
	 * @param file the output file
	 */

	protected void computeAndCompare(byte[] out, byte[] in, byte[] outBytes, byte[] key, PaddingParameterSpec padding, PrintWriter file) {
		
		//creates a SecretKey object out of the byte array key.
		SecretKey secretKey = new SecretKeySpec(key, "");
		try {
			
			//init the uh with the new secret key
			uh.init(secretKey, padding);
			
		
			//computes the hash computation
			uh.compute(in, 0, in.length, out, 0);
		} catch (UnInitializedException e) {
			//shouldn't be called since the object is initialized
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IllegalBlockSizeException e) {
			//shouldn't be called since the offsets and lengths are in the range
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (FactoriesException e) {
			//shouldn't be called since the padding is correct
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//if out is equal to the outbytes than result is set to true
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
		
		//writes the result to an output string
		String testResult = null;
		if (result){
			testResult = "Success: output is as expected";
		} else {
			testResult = "Failure: output is different from the expected " + expected;
		}
		
		//writes the test results to the given output file
		file.println(uh.getAlgorithmName() + "," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);
		
	}

	/**
	 * Runs all the required tests for uh. Each test can be either implemented in the derived hash test class
	 * or in this abstract class.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//call the wrong behavior functions
		unInited(file); //case that a function is called while the object is not initialized
		wrongOffset(file); //case that the given offset is not in the range
	}
	
	/**
	 * Tests the case that a function is called while the object is not initialized.
	 * the expected result is to throw UnInitializedException
	 * @param the output file
	 */
	private void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//sets the output size to be the same as the expected result length.
			byte [] out = new byte[(testDataVector.get(0).output).length];
			
			//computes without initialization
			uh.compute(testDataVector.get(0).input, testDataVector.get(0).input.length, 0, out, 0);
			
		//the expected result of this test is UnInitializedException
		}catch(UnInitializedException e){
			testResult = "Success: The expected exception \"UnInitializedException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"UnInitializedException\" was thrown";
		}
		
		//prints the result to the file
		file.println(uh.getAlgorithmName() + "," + provider + ",unInited,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that a compute function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//sets the output size to be the same as the expected result length.
			byte [] out = new byte[(testDataVector.get(0).output).length];
			
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(testDataVector.get(0).key, "");
			
			//init the uh with the new secret key
			uh.init(secretKey);
			
			//calls compute qith a wrong offsets
			uh.compute(testDataVector.get(0).input, testDataVector.get(0).input.length+1, testDataVector.get(0).input.length, out, out.length+1);
			//the expected result of this test is ArrayIndexOutOfBoundsException
		}catch(ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//prints the result to the file
		file.println(uh.getAlgorithmName() + "," + provider + ",Wrong offset,Wrong behavior,,," + testResult);
		
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
		PaddingParameterSpec padding;
		
		/**
		 * Sets the data
		 * @param padding 
		 */
		public TestData(byte[] input, byte[] output, byte[] key, PaddingParameterSpec padding) {
			this.input = input;
			this.output = output;
			this.key = key;
			this.padding = padding;
		}

	}
}
