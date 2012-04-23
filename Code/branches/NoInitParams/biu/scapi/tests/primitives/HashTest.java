package edu.biu.scapi.tests.primitives;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.tests.Test;

/**
 * Tests the CryptographicHash objects. <p>
 * This class has some goals:
 * The main goal is to check that cryptographic hash classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public abstract class HashTest extends Test {

	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	CryptographicHash hash;//the underlying hash 
	String provider = null;//the underlying hash provider name
	
	/**
	 * Sets the tested hash and its provider
	 * @param hash the underlying hash
	 */
	public HashTest(CryptographicHash hash) {
		
		this.hash = hash;
		
		//the class name contains the path, which contains the provider name
		//we save the provider name for further usage
		if (hash.getClass().toString().split("\\.")[5].equals("bc")){
			provider = "BC";
		} else if (hash.getClass().toString().split("\\.")[5].equals("cryptopp")){
			provider = "CryptoPP";
		} else {
			provider = "Scapi";
		}
	}

	/**
	 * 
	 * Adds one test data to the java vector testDataVector
	 * @param input the tested input
	 * @param output the expected output. The vector test will pass if the outcome of the computation will yield the byte array output
	 */
	protected void addData(byte[] input, byte[] output){
		
		//creates a new TestData object containing the inserted test vector
		TestData testData = new TestData(input, output);
		
		//adds to the java vector
		testDataVector.add(testData);
		
	}
	
	/**
	 * Creates a string that contains million characters of 'a.
	 * @return the million character a string
	 */
	protected String millionCharA(){
		
		//starts with 100 a's
		String thousand  ="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		String milion = thousand;
		
		//creates 1024,0000 a's
		for(int i=0; i<10;i++){
			milion += milion;
		}
		
		//cuts off the last a's so the string will contain only 1,000,000 a's
		milion = milion.substring(0, 1000000);
		
		return milion;
			
	}
	
	
	/**
	 * Convert from ASCII to byte array.
	 * @param input input string
	 * @return the resulted byte array.
	 */
	protected byte[] toByteArray(String input)
    {
		//the returned bytes array will have the same size as the input string since we translate from ASCII
        byte[] bytes = new byte[input.length()];
        
        //translates each character
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }
        
        return bytes;
    }
	
	/**
	 * Convert from byte array to ASCII.
	 * @param input input byte array
	 * @return the resulted ASCII string.
	 */
	protected String fromByteArray(byte[] input)
    {
		String convert = null;
        
        //translates each character
        for (int i = 0; i != input.length; i++)
        {
            convert = convert + Byte.toString(input[i]);
        }
        
        return convert;
    }
	

	
	/** 
	 * A general test. This can be done since the derived classes filled the vector of vector tests.
	 * Each data in the vector is tested and the test output is written to the output file
	 * @param file the output file
	 */
	public void testVector(PrintWriter file) {
		
		//the size of out should be as the size of the digest
		byte[] out = new byte[hash.getHashedMsgSize()]; 
		//goes over the test vector and tests each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//tests the test vector by calling computeAndCompare function. 
			computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output, file);
		}
		
	}
	
	/**
	 * 
	 * Computes the result of the hash and compares it with the expected output. 
	 * @param out byte array to fill the output of the hash function
	 * @param in the input to the hash function
	 * @param outBytes the expected output on the input in
	 * @param file the output file
	 */
	protected void computeAndCompare(byte[] out, byte[] in, byte[] outBytes, PrintWriter file) {
		
		//computes the hash computation
		hash.update(in, 0, in.length);
		hash.hashFinal(out, 0);
		
		
		//if out is equal to the outbytes, result is set to true
		boolean result =  Arrays.equals(out,outBytes);
		
		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		ByteArrayOutputStream inString = new ByteArrayOutputStream();
		ByteArrayOutputStream outString = new ByteArrayOutputStream();
		ByteArrayOutputStream outExString = new ByteArrayOutputStream();
		String input = null;
		String output = null;
		String testResult = null;
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
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//writes the result to a string
		if (result){
			testResult = "Success: output is as expected";
		} else {
			testResult = "Failure: output is different from the expected " + expected;
		}
		
		//writes the test results to the given output file
		file.println(hash.getAlgorithmName() + "," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);
		
	}
	
	/**
	 * Runs all the required wrong behavior tests for cryptographicHash. Each test can be either implemented in the derived hash test class
	 * or in this abstract class.
	 * @param file the output file
	 */
	protected void wrongBehavior(PrintWriter file){
		//calls the wrong behavior functions
		wrongOffset(file); //case that the offset to the update function is out of the range
		wrongLength(file); //case that the length to the update function is out of the range
			
	}
	
	/** 
	 * Tests the case that update function is called with a wrong offset.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongOffset(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets an input from the test vector
			byte [] in = testDataVector.get(0).input;
			//calls the update function with offset out of the input array range
			hash.update(in, in.length+2, in.length);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch(ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the file
		file.println(hash.getAlgorithmName() + "," + provider + ",Wrong offset,Wrong behavior,,," + testResult);
	}
	
	/** 
	 * Tests the case that update function is called with a wrong length.
	 * the expected result is to throw ArrayIndexOutOfBoundsException
	 * @param the output file
	 */
	private void wrongLength(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try {
			//gets an input from the test vector
			byte [] in = testDataVector.get(0).input;
			//calls the update function with length out of the input array range
			hash.update(in, 0, in.length+2);
			
		//the expected result of this test is ArrayIndexOutOfBoundsException
		} catch(ArrayIndexOutOfBoundsException e){
			testResult = "Success: The expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ArrayIndexOutOfBoundsException\" was thrown";
		}
		
		//writes the result to the output file
		file.println(hash.getAlgorithmName() + "," + provider + ",Wrong length,Wrong behavior,,," + testResult);
		
	}
	
	/**
	 * Nested TestData class, which is the data for the test vector.
	 * It contains the input and expected output
	 *
	 */
	class TestData{
		byte[] input;
		byte[] output; //expected output on the related input.
		
		/**
		 * Sets the data
		 */
		public TestData(byte[] input, byte[] output) {
			this.input = input;
			this.output = output;
		}
		
	}
	
	
}