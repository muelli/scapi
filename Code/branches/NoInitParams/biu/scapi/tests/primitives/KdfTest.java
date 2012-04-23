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
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.tests.Test;

/**
 * Tests the kdf objects. <p>
 * This class has some goals:
 * The main goal is to check that kdf classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class KdfTest extends Test {

	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	KeyDerivationFunction kdf;//the underlying kdf
	String provider = null; //the provider of the underlying kdf
	
	/**
	 * Sets the tested kdf and its provider
	 */
	public KdfTest(KeyDerivationFunction kdf) {

		this.kdf = kdf;
		
		//the class name contains the path, which contains the provider name
		//we save the provider name for further usage
		if (kdf.getClass().toString().split("\\.")[5].equals("bc")){
			provider = "BC";
		} else {
			provider = "Scapi";
		}
	}


	/**
	 * 
	 * Adds one test vector to the java vector testDataVector.
	 * @param input the tested input
	 * @param output the expected output. The vector test will pass if the outcome of the computation will yield the byte array output
	 * @param key the related secret key
	 * @param info info for the key generation
	 * @param outLen the required output length
	 */
	protected void addData(byte[] input, byte[] output, byte[] key, byte[] info, int outLen){

		TestData testData = new TestData(input, output, key, info, outLen);

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
			computeAndCompare(out, testDataVector.get(i).output, testDataVector.get(i).input, testDataVector.get(i).key, testDataVector.get(i).info, testDataVector.get(i).outLen, file);
		}

	}


	/**
	 * Computes the result of the kdf and compares it with the expected output. 
	 * @param out byte array to fill the output of the kdf function
	 * @param outBytes the expected output on the input in
	 * @param in the input to the kdf function
	 * @param key the related secret key
	 * @param info info for the key generation
	 * @param outLen the required output length
	 */
	protected void computeAndCompare(byte[] out, byte[] outBytes, byte[] in, byte[] key, byte[] info,int outLen, PrintWriter file) {

		//creates a SecretKey object out of the byte array key.
		SecretKey secretKey = new SecretKeySpec(in, "");

		//only if the kdf uses a key init the underlying kdf with this key.
		if(key!=null)
			try {
				kdf.setKey(new SecretKeySpec(key,""));
			} catch (InvalidKeyException e1) {
				//shouldn't be called since the vector test is known and correct
				Logging.getLogger().log(Level.WARNING, e1.toString());
			}
		
		SecretKey secretKeyOut = null;
		
		//generates new secretKey
		secretKeyOut = kdf.generateKey(secretKey, outLen, info);
		
		//puts the byte results in the out byte array
		out = secretKeyOut.getEncoded();
		
		//if out is equal to the outbytes than returns true
		boolean result =  Arrays.equals(out,outBytes);

		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		OutputStream inString = new ByteArrayOutputStream();
		OutputStream outString = new ByteArrayOutputStream();
		OutputStream outExString = new ByteArrayOutputStream();
		String input = null, output = null;
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
		file.println("KDF," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);

	}

	/**
	 * Runs all the required wrong behavior tests for kdf. Each test can be either implemented in the derived kdf test class
	 * or in this abstract class.
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions
		unInited(file); //case that a function is called while the object is not initialized
		wrongOffset(file); //case that the given offset to the generateKey function is not in the range
		wrongLength(file);  //case that the given length to the generateKey function is not in the range
		badCasting(file); //case that the input was casted badly
	}

	/**
	 * Tests the case that a function generateKey is called while the object is not initialized.
	 * the expected result is to throw UnInitializedException
	 * @param the output file
	 */
	private void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets the inputs from the test vector
			byte[] input = testDataVector.get(0).input;
			SecretKey secretKey = new SecretKeySpec(input, "");
			//calls generateKey without initialization
			kdf.generateKey(secretKey, 100);
		
		//the expected result of this test is IllegalStateException
		} catch (IllegalStateException e){
			testResult = "Success: The expected exception \"IllegalStateException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalStateException\" was thrown";
		}
		
		//prints the result to the file
		file.println("KDF," + provider + ",unInited,Wrong behavior,,," + testResult);
		
	}

	/** 
	 * Tests the case that a generakeKey function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	protected void wrongOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets the inputs from the test vector
			byte[] input = testDataVector.get(0).input;
			byte[] key =  testDataVector.get(0).key;
			byte[] info = testDataVector.get(0).info;
			byte[] outKey = new byte[100];
			if (key!=null){
				//init the kdf
				kdf.setKey(new SecretKeySpec(key,""));
			}
			//calls generateKey with a wrong offset
			kdf.generateKey(input, input.length+2, input.length, outKey, outKey.length+2, 100, info);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//prints the result to the output file
		file.println("KDF," + provider + ",Wrong offset,Wrong behavior,,," + testResult);
	}
	
	/** 
	 * Tests the case that a generakeKey function is called with a wrong length.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	protected void wrongLength(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets the inputs from the test vector
			byte[] input = testDataVector.get(0).input;
			byte[] key =  testDataVector.get(0).key;
			byte[] outKey = new byte[100];
			byte[] info = testDataVector.get(0).info;
			if (key!=null){
				//init the kdf
				kdf.setKey(new SecretKeySpec(key,""));
			}
			//calls generateKey with a wrong length
			kdf.generateKey(input, 0, input.length+2, outKey, 0, 102, info);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch (ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is a failure	
		} catch (Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//prints the result to the output file
		file.println("KDF," + provider + ",Wrong length,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that the given argument is not match the argument type
	 * the expected result is to throw ClassCastException
	 * @param the output file
	 */
	private void badCasting(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//tries to initialize with a public key instead of secretkey
			kdf.setKey((SecretKey) new RSAPublicKeySpec(null, null));
		
		//the expected result of this test is ClassCastException
		} catch (ClassCastException e){
			testResult = "Success: The expected exception \"ClassCastException\" was thrown";
		//any other exception is a failure		
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ClassCastException\" was thrown";
		}
		
		//prints the result to the output file
		file.println("KDF," + provider + ",Bad casting,Wrong behavior,,," + testResult);

	}
	
	/**
	 * Nested TestData class, which is the data for the test vector.
	 * It contains the input, expected output, key, info for generation and the required output length
	 *
	 */
	class TestData{
		byte[] input;
		byte[] output;
		byte[] key;
		byte[] info;
		int outLen;

		/**
		 * Sets the data
		 */
		public TestData(byte[] input, byte[] output, byte[] key, byte[] info, int outLen) {
			this.input = input;
			this.output = output;
			this.key = key;
			this.outLen = outLen;
			this.info = info;
		}

	}
}