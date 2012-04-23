package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Vector;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.ECElement;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;

/**
 * This class tests the performance and correctness of any implemented Dlog group over elliptic curves.
 * There is no known test vectors.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class DlogECTest extends DlogGroupTest{

	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	
	/**
	 * Sets the given DlogEC object.
	 */
	public DlogECTest(DlogGroup dlog) {
		super(dlog);
	}
	
	/**
	 * Adds one test data to the java vector testDataVector.
	 * @param params the name of the elliptic curve
	 * @param x the exponent to the exponentiate function
	 * @param xElement the x coordinate of the element to be raised to the exponent
	 * @param yElement the y coordinate of the element to be raised to the exponent
	 * @param xOutput the x coordinate of the expected result
	 * @param yOutput the y coordinate of the expected result
	 */
	protected void addData(DlogGroup dlog, BigInteger x, BigInteger xElement, BigInteger yElement, BigInteger xOutput, BigInteger yOutput){
		//added new test data with the inputs
		testDataVector.add(new TestData(dlog, x, xElement, yElement, xOutput, yOutput));
	}
	
	/** 
	 * A general test. This can be done since the derived classes filled the vector of vector tests.
	 * each data in the vector is tested and the test output is written to the output file
	 * @param file the output file
	 */
	public void testVector(PrintWriter file){ 

		//goes over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){

			//tests the test vector by calling computeAndCompare function. 
			computeAndCompare(testDataVector.get(i).dlog, testDataVector.get(i).x, testDataVector.get(i).xElement, 
					testDataVector.get(i).yElement, testDataVector.get(i).xOutput, testDataVector.get(i).yOutput, file);
		}
		super.testVector(file);
	}
	
	/**
	 * Computes the exponentiate function of dlog group and compares the result with the expected output.
	 * @param params the name of the elliptic curve
	 * @param x the exponent to the exponentiate function
	 * @param xElement the x coordinate of the element to be raised to the exponent
	 * @param yElement the y coordinate of the element to be raised to the exponent
	 * @param xOutput the x coordinate of the expected result
	 * @param yOutput the y coordinate of the expected result
	 * @param file the output file
	 */
	private void computeAndCompare(DlogGroup dlogGroup, BigInteger exponent, BigInteger xElement, BigInteger yElement, BigInteger xOutput, BigInteger yOutput, PrintWriter file) {
		String testResult = null; //the test result. 
		
		DlogEllipticCurve dlog = (DlogEllipticCurve) dlogGroup;
		GroupElement element = ((DlogEllipticCurve) dlog).getElement(xElement, yElement);
	
		//computes element^x
		GroupElement eExpX = dlog.exponentiate(element, exponent);
		//gets the points coordinates
		BigInteger x_eExpX = ((ECElement) eExpX).getX();
		BigInteger y_eExpX = ((ECElement) eExpX).getY();
		
		//compares the points
		if(x_eExpX.equals(xOutput) && y_eExpX.equals(yOutput)){
			testResult = "Success: output is as expected";
		} else{
			testResult = "Failure: element is different from the expected";
		}
		
		//prints the test result to the output file
		file.println(dlog.getGroupType()+"," + provider + ",Compute and compare,Test vector,,,"+testResult);
	}
	
	/** 
	 * Tests the case that the argument to a dlog function is not match the dlog type
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */	
	protected void wrongArgumentType(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//creates a dlog over Zp in order to get an element of Zp type
			
			ZpGroupParams params = new ZpGroupParams(new BigInteger("22"), new BigInteger("3"), new BigInteger("11"));
			CryptoPpDlogZpSafePrime dlogTemp = new CryptoPpDlogZpSafePrime(params);
			//get the Zp generator
			GroupElement element = dlogTemp.getGenerator();
			
			//calls the exponentiate function with the Zp element
			dlog.exponentiate(element, new BigInteger("3"));
			
		//the expected result of this test is IllegalArgumentException	
		}catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",Wrong argument type,Wrong behavior,,," + testResult);
	}
	
	
	
	/**
	 * Nested TestData class, which is the data for the test vector.
	 * It contains the group params, input element, exponent and expected output 
	 *
	 */
	class TestData{
		DlogGroup dlog;
		BigInteger x;
		BigInteger xElement;
		BigInteger yElement;
		BigInteger xOutput;
		BigInteger yOutput;
		
		/**
		 * Sets the data
		 * @param params the name of the elliptic curve
		 * @param x the exponent to the exponentiate function
		 * @param xElement the x coordinate of the element to be raised to the exponent
		 * @param yElement the y coordinate of the element to be raised to the exponent
		 * @param xOutput the x coordinate of the expected result
		 * @param yOutput the y coordinate of the expected result
		 */
		public TestData(DlogGroup dlog, BigInteger x, BigInteger xElement, BigInteger yElement, BigInteger xOutput, BigInteger yOutput){
			this.dlog = dlog;
			this.x = x;
			this.xElement = xElement;
			this.yElement = yElement;
			this.xOutput = xOutput;
			this.yOutput = yOutput;
		}
	}

}
