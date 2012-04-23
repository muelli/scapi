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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.prg.PseudorandomGenerator;
import edu.biu.scapi.tests.Test;

/**
 * Tests the prg objects. <p>
 * This class has some goals:
 * The main goal is to check that prg classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class PrgTest extends Test {
		
	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	PseudorandomGenerator prg;//the underlying prg
	String provider = null; //the provider of the underlying prg
	
	/**
	 * Sets the tested prg and its provider
	 */
	public PrgTest(PseudorandomGenerator prg) {
		
		this.prg = prg;
		if (prg.getClass().toString().split("\\.")[5].equals("bc")){
			provider = "BC";
		} else {
			provider = "Scapi";
		}
	}
	
	/**
	 * 
	 * Adds one test vector to the java vector testDataVector.
	 * @param len the required output length
	 * @param output the expected output. The vector test will pass if the outcome of the computation will yield the byte array output
	 * @param key the related secret key
	 */
	protected void addData(int len, byte[] output, byte[] key){
		//creates new testData and adds it to the test vector
		TestData testData = new TestData(len, output, key);
		
		testDataVector.add(testData);
		
	}

	/** 
	 * A general test. This can be done since the derived classes filled the vector of vector tests.
	 * each data in the vector is tested and the test output is written to the output file
	 * @param file the output file
	 */
	public void testVector(PrintWriter file) {
		
		byte[] out;  
		//goes over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//sets the output size to be the same as the expected result length.
			out = new byte[(testDataVector.get(i).output).length];
			
			//tests the test vector by calling computeAndCompare function. 
			computeAndCompare(out, testDataVector.get(i).len, testDataVector.get(i).output, testDataVector.get(i).key, file);
		}
	}
	
	
	/**
	 * Computes the result of the prg and compares it with the expected output. 
	 * @param out byte array to fill the output of the prg function
	 * @param len the required output length
	 * @param outBytes the expected output on the input in
	 * @param key the key for the prg
	 * @param file the output file
	 */
	protected void computeAndCompare(byte[] out, int len, byte[] outBytes, byte[] key, PrintWriter file) {
		
		//creates a SecretKey object out of the byte array key.
		SecretKey secretKey = new SecretKeySpec(key, "");
		
		//init the prg with the new secret key
		try {
			prg.setKey(secretKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	
		//computes the function
		prg.getPRGBytes(out, 0, out.length);
		
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
			Hex.encode(key, inString);
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
		
		//prints the test results to the given output file
		file.println(prg.getAlgorithmName() + "," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);
		
	}

	/**
	 * Runs all the required wrong behavior tests for prg. Each test can be either implemented in the derived hash test class
	 * or in this abstract class.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//call the wrong behavior functions
		unInited(file); //case that a function is called while the object is not initialized
		wrongOffset(file); //case that the given offset is not in the range
		wrongLength(file); //case that the given length is not in the range
		badCasting(file); //case that the input was casted badly
	}
	
	
	/** 
	 * Tests the case that a getPRGBytes function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(Hex.decode("0123456789abcdef"), "");
			byte[] out = new byte[1000];
			
			//init the prg with the new secret key
			prg.setKey(secretKey);
			
			//computes the function
			prg.getPRGBytes(out, out.length+2, out.length);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is a failure
		}catch (Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the output file
		file.println(prg.getAlgorithmName() + "," + provider + ",Wrong offset,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that a getPRGBytes function is called with a wrong length.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongLength(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//creates a SecretKey object out of the byte array key.
			SecretKey secretKey = new SecretKeySpec(Hex.decode("0123456789abcdef"), "");
			byte[] out = new byte[100];
			
			//init the prg with the new secret key
			prg.setKey(secretKey);
			
			//computes the function
			prg.getPRGBytes(out, 0, out.length+2);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is a failure
		}catch (Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the output file
		file.println(prg.getAlgorithmName() + "," + provider + ",Wrong length,Wrong behavior,,," + testResult);
		
	}

	/**
	 * Tests the case that a function is called while the object is not initialized.
	 * the expected result is to throw UnInitializedException
	 * @param the output file
	 */
	private void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			byte[] out = new byte[100];
			
			//computes the function without initialization
			prg.getPRGBytes(out, 0, out.length);
		//the expected result of this test is UnInitializedException
		} catch (IllegalStateException e){
			testResult = "Success: The expected exception \"IllegalStateException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalStateException\" was thrown";
		}
		
		//writes the result to the output file
		file.println(prg.getAlgorithmName() + "," + provider + ",unInited,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that the given argument is not match the argument type
	 * the expected result is to throw ClassCastException
	 * @param the output file
	 */
	private void badCasting(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//init the prg with a public key casted to secretKey
			prg.setKey((SecretKey) new RSAPublicKeySpec(null, null));
			
		//the expected result of this test is ClassCastException
		} catch (ClassCastException e) {
			testResult = "Success: The expected exception \"ClassCastException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ClassCastException\" was thrown";
		}
		
		//writes the result to the output file
		file.println(prg.getAlgorithmName() + "," + provider + ",Bad casting,Wrong behavior,,," + testResult);
		
	}
	
	/**
	 * Nested TestData class, which is the data for the test vector.
	 * It contains the required length, expected output and the key
	 *
	 */
	class TestData{
		int len;
		byte[] output;
		byte[] key;
		
		/**
		 * Sets the data
		 */
		public TestData(int len, byte[] output, byte[] key) {
			this.len = len;
			this.output = output;
			this.key = key;
		}
		
	}
}