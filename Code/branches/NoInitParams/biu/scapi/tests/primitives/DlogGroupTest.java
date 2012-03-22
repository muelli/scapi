package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.tests.Test;

/**
 * Tests the FlogGroup objects. <p>
 * This class has some goals:
 * The main goal is to check that dlog classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class DlogGroupTest extends Test {
	DlogGroup dlog;//the underlying dlog
	String provider = null; //the underlying dlog provider name 
	
	/**
	 * Sets the tested dlog.
	 * @param dlog the tested object
	 */
	public DlogGroupTest(DlogGroup dlog) {
		
		this.dlog = dlog;
		
		//saves the provider name to further use. 
		//the class name contains the path which contains the provider name
		if (dlog.getClass().toString().split("\\.")[5].equals("bc")){
			provider = "BC";
		} else if (dlog.getClass().toString().split("\\.")[5].equals("miracl")){
			provider = "Miracl";
		} else if (dlog.getClass().toString().split("\\.")[5].equals("cryptopp")){
			provider = "CryptoPP";
		} else {
			provider = "Scapi";
		}
	}
	
	/**
	 * Runs test vector on the tested dlog.
	 * This is an abstract method that every test class of dlog group must implement.
	 * @param file the results file
	 */
	public void testVector(PrintWriter file){
		conversionsTest(file);
	}

	/**
	 * Tests the conversions from GroupElement to bite array and vice versa
	 * @param file output file
	 */
	protected abstract void conversionsTest(PrintWriter file);
	
	/**
	 * Runs all the required wrong behavior tests of Dlog group. 
	 * Each test can be either implemented in the derived dlog test class
	 * or in this abstract class.
	 * @param file the results file
	 */
	public void wrongBehavior(PrintWriter file) {
		//calls the wrong behavior functions
		unInited(file); //case that a method is called without initialization of the object
		wrongArgumentType(file); //case that the input for a function is not matches the tested object
		wrongElementInput(file); //case that the input for an element of the tested dlog is wrong 
		
	}

	/**
	 * Test the case that the given argument does not match the dlog group.
	 * This test implemented in the derived classes
	 * @param file the results file
	 */
	protected abstract void wrongArgumentType(PrintWriter file);
	
	/**
	 * Test the case that a dlog element constructor gets a wrong arguments.
	 * This test implemented in the derived classes.
	 * @param file the results file
	 */
	protected abstract void wrongElementInput(PrintWriter file);
	
	/**
	 * Test the case that a function is called before the object was initialized.
	 * @param file the results file
	 */
	private void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{ //calls the getGenerator function before initialization
			dlog.getGenerator();
		}catch(UnInitializedException e){
			// the expected exception was thrown - result is sets to success
			testResult = "Success: The expected exception \"UnInitializedException\" was thrown";
		//any other exception is wrong
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"UnInitializedException\" was thrown";
		}
		
		//prints the results to the given output file
		file.println(dlog.getGroupType() + "," + provider + ",unInited,Wrong behavior,,," + testResult);
		
	}
	
}