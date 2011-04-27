/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import java.util.Arrays;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.crypto.prf.PseudorandomFunction;
import edu.biu.scapi.tests.Test;

/**
 * 
 * @author LabTest
 *
 */
public abstract class PrfTest implements Test {
	
	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	PseudorandomFunction prf;//the underlying prf
	
	/**
	 * 
	 */
	public PrfTest(PseudorandomFunction prf) {
		
		this.prf = prf;
	}
	
	/**
	 * runTest - runs all the required tests for prf. Each test can be either implemented in the derived hash test class
	 * 			 or in this abstract class.
	 */
	public void runTest() {

		//call the derived classes implementation. 
		testVector(); 
		wrongKeySize(); 
		wrongKeyEncoding(); 
		wrongKeyType(); 
		unInited(); 
		wrongOffset(); 
		wrongAlgSpec(); 

	}

	/**
	 * 
	 * addData - adds one test vector to the java vector testDataVector
	 * @param input - the tested input
	 * @param output - the expected output. The vector test will pass if the outcome of the computation will yield the byte array output.
	 * @param key - the related secret key
	 */
	protected void addData(byte[] input, byte[] output, byte[] key){
		
		TestData testData = new TestData(input, output, key);
		
		testDataVector.add(testData);
		
	}
	
	/** 
	 * 
	 * testVector - a general test. This can be done since the derived classes filled the vector of vector tests.
	 * @return - true is the test has passed, otherwise false = fail.
	 */
	
	public boolean testVector() {

		boolean ret = true;
		
		byte[] out;  
		//go over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//set the output size to be the same as the expected result length.
			out = new byte[(testDataVector.get(i).output).length];
			
			//test the test vector by calling computeAndCompare function. If it fails, the function testVector fails too (due to the AND (&&) operation
			ret = ret && computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output, testDataVector.get(i).key);
		}
		return ret;
		
	}
	
	
	/**
	 * 
	 * computeAndCompare computes the result of the prf and compares it with the expected output. 
	 * @param out - byte array to fill the output of the prf function
	 * @param in - the input to the prf function
	 * @param outBytes - the expected output on the input in
	 * @return true - if the output of the function is equal to the expected output, false otherwise.
	 */

	protected boolean computeAndCompare(byte[] out, byte[] in, byte[] outBytes, byte[] key) {
		
		//create a SecretKey object out of the byte arrat key.
		SecretKey secretKey = new SecretKeySpec(key, "");
		
		//init the prf with the new secret key
		prf.init(secretKey);
		
		try {
			//compute the function
			prf.computeBlock(in, 0, in.length, out, 0, out.length);
		} catch (IllegalBlockSizeException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		//if out is equal to the outbytes than return true
		boolean ret =  Arrays.equals(out,outBytes);
		
		System.out.println("result is: " + ret + " on algorithm "  + prf.getAlgorithmName());
		
		return ret;
	}

	/**
	 * 
	 * wrongKeySize
	 */
	public void wrongKeySize() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 * wrongKeyEncoding
	 */
	public void wrongKeyEncoding() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 * wrongKeyType
	 */
	public void wrongKeyType() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 * unInited
	 */
	public void unInited() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
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

	/** 
	 * 
	 * wrongAlgSpec
	 */
	public void wrongAlgSpec() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
	
	//nested TestData class
	class TestData{
		byte[] input;
		byte[] output;
		byte[] key;
		/**
		 * 
		 */
		public TestData(byte[] input, byte[] output, byte[] key) {
			this.input = input;
			this.output = output;
			this.key = key;
		}
		
	}
	
}