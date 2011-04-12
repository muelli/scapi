/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import java.util.Arrays;
import java.util.Vector;

import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;
import edu.biu.scapi.tests.Test;

/**
 * 
 * @author LabTest
 *
 * An abstract class for testing collision resistant hash.
 */
public abstract class HashTest implements Test {

	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	TargetCollisionResistant tcr;//the underlying hash 
	
	/**
	 * 
	 * @param tcr - the underlying hash. The hash we test
	 */
	public HashTest(TargetCollisionResistant tcr) {
		
		this.tcr = tcr;
	}

	/**
	 * runTest - runs all the required tests for hash. Each test can be either implemented in the derived hash test class
	 * 			 or in this abstract class.
	 */
	public void runTest() {

		//run the test vector
		testVector();
		
		//run wrong offset test
		wrongOffset();
	}

	/**
	 * 
	 * addData - adds one test vector to the java vector testDataVector
	 * @param input - the tested input
	 * @param output - the expected output. The vector test will pass if the outcome of the computation will yield the byte array output.
	 */
	protected void addData(byte[] input, byte[] output){
		
		//create a new TestData object containing the inserted test vector
		TestData testData = new TestData(input, output);
		
		//add to the java vector
		testDataVector.add(testData);
		
	}
	
	/**
	 * 
	 * millionCharA - creates a string that contains million characters of 'a
	 * @return - the million charater a string
	 */
	protected String millionCharA(){
		
		//start with 100 a's
		String thousand  ="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		String milion = thousand;
		
		//create 1024,0000 a's
		for(int i=0; i<10;i++){
			milion += milion;
		}
		
		//cut off the last a's so the string will contain only 1000,000 a's
		milion = milion.substring(0, 1000000);
		
		return milion;
			
	}
	
	
	/**
	 * 
	 * toByteArray - from ASCII to byte array.
	 * @param input - input string
	 * @return resulted byte array.
	 */
	protected byte[] toByteArray(String input)
    {
		//the returned bytes arrat will have the same size as the input string since we translate from ASCII
        byte[] bytes = new byte[input.length()];
        
        //translate each character
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }
        
        return bytes;
    }

	
	/** 
	 * 
	 * testVector - a general test. This can be done since the derived classes filled the vector of vector tests.
	 * @return - true is the test has passed, otherwise false = fail.
	 */
	public boolean testVector() {
		
		boolean ret = true;
		
		//the size of out should be as the size of the digest
		byte[] out = new byte[tcr.getHashedMsgSize()]; 
		//go over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//test the test vector by calling computeAndCompare function. If it fails, the function testVector fails too (due to the AND (&&) operation 
			ret = ret && computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output);
		}
		return ret;
	}
	
	/**
	 * 
	 * computeAndCompare computes the result of the hash and compares it with the expected output. 
	 * @param out - byte array to fill the output of the hash function
	 * @param in - the input to the hash function
	 * @param outBytes - the expected output on the input in
	 * @return true - if the output of the function is equal to the expected output, false otherwise.
	 */
	protected boolean computeAndCompare(byte[] out, byte[] in, byte[] outBytes) {
		
		
	
		//compute the hash
		tcr.update(in, 0, in.length);
		tcr.hashFinal(out, 0);
		
		//if out is equal to the outbytes than return true
		boolean ret =  Arrays.equals(out,outBytes);
		
		System.out.println("result is: " + ret + " on algorithm "  + tcr.getAlgorithmName());
		
		return ret;
	}
	
	
	
	/**
	 * 
	 * wrongOffset
	 */
	public void wrongOffset() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
	
	//nested TestData class
	class TestData{
		byte[] input;
		byte[] output; //expected output on the related input.
		/**
		 * 
		 */
		public TestData(byte[] input, byte[] output) {
			this.input = input;
			this.output = output;
		}
		
	}
	
	
}