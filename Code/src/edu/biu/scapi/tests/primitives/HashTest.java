/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import java.util.Arrays;
import java.util.Vector;

import edu.biu.scapi.primitives.crypto.hash.TargetCollisionResistant;
import edu.biu.scapi.tests.Test;

/** 
 * <!-- begin-UML-doc -->
 * <!-- end-UML-doc -->
 * @author LabTest
 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
 */
public abstract class HashTest implements Test {

	Vector<TestData> testDataVector= new Vector<TestData>();
	TargetCollisionResistant tcr;
	
	public HashTest(TargetCollisionResistant tcr) {
		
		this.tcr = tcr;
	}

	
	public void runTest() {

		testVector();
		wrongOffset();
	}

	protected void addData(byte[] input, byte[] output){
		
		TestData testData = new TestData(input, output);
		
		testDataVector.add(testData);
		
	}
	
	protected String millionCharA(){
		
		//start with 100 a's
		String thousand  ="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		String milion = thousand;
		
		//create 1024,0000 a's
		for(int i=0; i<10;i++){
			milion += milion;
		}
		
		//cut the a's to be only 1000,000
		
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
        byte[] bytes = new byte[input.length()];
        
        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }
        
        return bytes;
    }

	
	/** 
	 * 
	 * testVector
	 * @return
	 */
	public boolean testVector() {
		
		boolean ret = true;
		
		byte[] out = new byte[tcr.getHashedMsgSize()]; 
		//go over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			ret = ret && computeAndCompare(out, testDataVector.get(i).input, testDataVector.get(i).output);
		}
		return ret;
	}


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
		byte[] output;
		/**
		 * 
		 */
		public TestData(byte[] input, byte[] output) {
			this.input = input;
			this.output = output;
		}
		
	}
	
	
}