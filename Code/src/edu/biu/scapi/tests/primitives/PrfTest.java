/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import java.util.Arrays;
import java.util.Vector;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.primitives.crypto.prf.PseudorandomFunction;
import edu.biu.scapi.tests.Test;

/**
 * 
 * @author LabTest
 *
 */
public abstract class PrfTest implements Test {
	
	Vector<TestData> testDataVector= new Vector<TestData>();
	PseudorandomFunction prf;
	
	/**
	 * 
	 */
	public PrfTest(PseudorandomFunction prf) {
		
		this.prf = prf;
	}
	
	/**
	 * runTest : 
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

	protected void addData(byte[] input, byte[] output, byte[] key){
		
		TestData testData = new TestData(input, output, key);
		
		testDataVector.add(testData);
		
	}
	
	/**
	 * 
	 * testVector
	 * @return
	 */
	public boolean testVector() {

		boolean ret = true;
		
		byte[] out;  
		//go over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//set the output size to be the same as the expected result length.
			out = new byte[(testDataVector.get(i).output).length];
			ret = ret && computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output, testDataVector.get(i).key);
		}
		return ret;
		
	}
	
	
	/**
	 * computeAndCompare
	 * @param out
	 * @param in
	 * @param key3
	 * @param aes
	 * @param outBytes 
	 */
	protected boolean computeAndCompare(byte[] out, byte[] in, byte[] outBytes, byte[] key) {
		SecretKey secretKey = new SecretKeySpec(key, "");
		
		prf.init(secretKey);
		
		try {
			prf.computeBlock(in, 0, in.length, out, 0, out.length);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
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