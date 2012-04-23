package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;

import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class tests the performance and correctness of any implemented elliptic curve DlogGroup over F2m algorithm.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class DlogECF2mTest extends DlogECTest{
	
	/**
	 * sets the tested dlog
	 * @param dlog the tested object
	 */
	public DlogECF2mTest(DlogGroup dlog) {
		super(dlog);	
	}
	
	protected void conversionsTest(PrintWriter file){
		String testResult = null; //the test result. initialized to failure
		try {
			
			//converts the generator to byte array
			GroupElement generator= dlog.getGenerator();
			byte[] gBytes = dlog.convertGroupElementToByteArray(generator);
			//converts back to the generator
			GroupElement backToGenerator = dlog.convertByteArrayToGroupElement(gBytes);
			
			//checks if the converted element is equal to the generator
			if (generator.equals(backToGenerator)){
				testResult = "Success: The conversions from GroupElement to byte array and vice versa succeeded";
			} else {
				testResult = "Failure: The conversions from GroupElement to byte array and vice versa failed";
			}
		} catch (Exception e){
			if (e.getMessage().equals("Create an ECF2mPointBC element will be available as soon as BC implements the sqrt function in ECFieldElement.F2m")){
				testResult = "Success: A RuntimeException was thrown as expected. BC didn't implement the sqrt function so we can't calculate the y coordinate via the elliptic curve equation.";
			}
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",conversionsTest,Test vector,,," + testResult);
	}
	
	/** 
	 * Tests the case that the argument to the constructor of a dlog element is not legal element value
	 * the expected result is to throw IllegalArgumentException
	 * @param the output file
	 */	
	protected void wrongElementInput(PrintWriter file){
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			
			//create an element which is not valid to this dlog
			((DlogEllipticCurve) dlog).getElement(new BigInteger("5"), new BigInteger("5"));
			
		//the expected result of this test is IllegalArgumentException
		}catch(IllegalArgumentException e){
			testResult = "Success: The expected exception \"IllegalArgumentException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"IllegalArgumentException\" was thrown";
		}
		
		//writes the result to the file
		file.println(dlog.getGroupType() + "," + provider + ",wrong Element Input,Wrong behavior,,," + testResult);
		
	}
	
}
