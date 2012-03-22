package edu.biu.scapi.tests.primitives;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.primitives.trapdoorPermutation.TPElement;
import edu.biu.scapi.primitives.trapdoorPermutation.TrapdoorPermutation;
import edu.biu.scapi.tests.Test;

/**
 * Tests the trapdoor permutation objects. <p>
 * This class has some goals:
 * The main goal is to check that tp classes meets the requirements. 
 * A secondary goal is to find bugs and undesired behavior. 
 * We aim to detect software failures so that defects may be discovered and corrected. 
 * We also want to make sure that new bugs are not introduced in new versions.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class TrapdoorPermutationTest extends Test {

	
	TrapdoorPermutation tp;//the underlying tp
	Vector<TestData> testDataVector= new Vector<TestData>();//holds the test vectors in each TestData object
	Vector<TestDataInvertCompute> testDataInvertCompute = new Vector<TestDataInvertCompute>();//holds the tests to check that the input returns to its original value after compute and invert in each TestData object
	String provider = null; // the provider of the underlying tp
	
	public TrapdoorPermutationTest(TrapdoorPermutation tp) {
		this.tp = tp;
		
		//the class name contains the path, which contains the provider name
		//we save the provider name for further usage
		if (tp.getClass().toString().split("\\.")[5].equals("cryptopp")){
			provider = "CryptoPP";
		} else {
			provider = "Scapi";
		}
	}
	
	/**
	 * 
	 * addData - adds one test data to the vector testDataVector for the compute and compare function
	 * @param input - the tested input
	 * @param output - the expected output. The vector test will pass if the outcome of the computation will yield the byte array output.
	 * @param publicKey - the related public key
	 * @param privateKey - the related private key
	 */
	protected void addData(TPElement input, TPElement computeOutput, PublicKey publicKey, PrivateKey privateKey){
		//creates a testData and adds it to the test vector
		TestData testData = new TestData(input, computeOutput, publicKey, privateKey);
		
		testDataVector.add(testData);
		
	}
	
	/**
	 * 
	 * Adds one testData with input and keys to the vector testDataInvertcompute for the compute and invert compare function.
	 * @param input - the tested input
	 * @param publicKey - the related public key
	 * @param privateKey - the related private key
	 */
	protected void addDataInvertCompute(TPElement input, PublicKey publicKey, PrivateKey privateKey){
		//creates a test Data with the input and keys and adds it to the vector
		TestDataInvertCompute testInvertComputeData = new TestDataInvertCompute(input,publicKey, privateKey);
		
		testDataInvertCompute.add(testInvertComputeData);
		
	}
	
	/**
	 * 
	 * Adds one test data with input and algorithm parameter spec to the vector testDataInvertcompute.
	 * @param input - the tested input
	 * @param spec auxiliary parameters
	 */
	protected void addDataInvertCompute(TPElement input, AlgorithmParameterSpec spec){
		//creates a test Data with the input and algorithmParameterSpec and adds it to the vector
		TestDataInvertCompute testInvertComputeData = new TestDataInvertCompute(input,spec);
		
		testDataInvertCompute.add(testInvertComputeData);
		
	}
	
	/** 
	 * A general test that computes the trapdoor operation and checks that the result is as expected. 
	 * This can be done since the derived classes filled the vector of vector tests.
	 * Each data in the vector is tested and the test output is written to the output file.
	 * @param file the output file
	 */
	public void testVector(PrintWriter file) {
		  
		//goes over the test vector and test each data.
		for(int i=0; i<testDataVector.size();i++){
			
			//tests the test vector by calling computeAndCompare function. 
			computeAndCompare(testDataVector.get(i).input, testDataVector.get(i).output, 
										   testDataVector.get(i).publicKey, testDataVector.get(i).privateKey, file);
		}
		//call to a function that checks the compute-invert operations
		testInvertCompute(file);	
	}
	
	/** 
	 * A general test that computes the trapdoor operation, than inverts the operation and checks that the result is as the input to the compute. 
	 * This can be done since the derived classes filled the vector of vector tests.
	 * Each data in the vector is tested and the test output is written to the output file.
	 * @param file the output file
	 */
	protected void testInvertCompute(PrintWriter file){
		  
		//goes over the test vector and test each data.
		for(int i=0; i<testDataInvertCompute.size();i++){
			
			//tests the test vector by calling computeAndInvertCompare function. 
			computeAndInvertCompare(testDataInvertCompute.get(i).input,  
					testDataInvertCompute.get(i).publicKey, testDataInvertCompute.get(i).privateKey, testDataInvertCompute.get(i).spec, file);
		}
		
	}

	/**
	 * 
	 * Computes the result of the trapdoor operation on the given TPElement and compares it with the expected output. 
	 * @param value The input element
	 * @param computeOutput The computation result 
	 * @param publicKey the related public key
	 * @param privateKey the related private key
	 * @param file output file
	 */
	private void computeAndCompare(TPElement value, TPElement computeOutput, PublicKey pub, PrivateKey priv, PrintWriter file) {
		boolean result = false;
		TPElement computeResult = null;
		try {
			//init the trapdoor with the keys
			tp.init(pub, priv);
			
			//computes the function
			computeResult = tp.compute(value);
			
			//if computeResult is equal to the expected computeOutput, result is set to true
			if (computeResult.getElement().compareTo(computeOutput.getElement()) == 0)
					result = true;
			
		} catch (InvalidKeyException e) {
			//should not occur since the keys are from the test vector
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IllegalArgumentException e) {
			//should not occur since the elements are from the test vector
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (UnInitializedException e) {
			//should not occur since the object is initialized
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		
		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		String expected = computeOutput.getElement().toString();
		if (expected.length()>100){
			expected = expected.substring(0,99)+"...";
		}
		String input =  value.getElement().toString();
		if (input.length()>100){
			input = input.substring(0,99)+"...";
		}
		String output = computeResult.getElement().toString();
		if (output.length()>100){
			output = output.substring(0,99)+"...";
		}
		
		//writes the result to a string
		String testResult = null;
		if (result){
			testResult = "Success: output is as expected";
		} else {
			testResult = "Failure: output is different from the expected " + expected;
		}
		
		//prints the test results to the given output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Compute and compare,Test vector," + input + "," + output + ","+testResult);
		
	}
	
	/**
	 * 
	 * Computes the trapdoor operatior, inverts it and compares the invert result to the compute input. 
	 * @param value The input element 
	 * @param publicKey the related public key
	 * @param privateKey the related private key
	 * @param spec auxiliary parameters
	 * @param file output file
	 */

	private void computeAndInvertCompare(TPElement value, PublicKey pub, PrivateKey priv, AlgorithmParameterSpec spec, PrintWriter file) {
		boolean result = false;
		TPElement computeResult, invertResult = null;
		try {
			//if the algorithmParameterSpec is null, init the object with the keys, else, init with the algorithmParameterSpec
			if(spec==null){
				tp.init(pub, priv);
			}
			else
				tp.init(spec);
			
			//if there is no input element, gets a random element
			if(value==null)
				value = tp.getRandomTPElement();
			
			//computes the function
			computeResult = tp.compute(value);
			//inverts the computed value
			invertResult = tp.invert(computeResult);
			
			//checks that the invert result is equal to the original value
			if (invertResult.getElement().compareTo(value.getElement()) == 0)
				result = true;
			
		} catch (InvalidKeyException e) {
			//should not occur since the keys are from the test vector
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (IllegalArgumentException e) {
			//should not occur since the elements are from the test vector
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (UnInitializedException e) {
			//should not occur since the object is initialized
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		} catch (InvalidParameterSpecException e) {
			//should not occur since the algorithmParameterSpec is from the test vector
			e.printStackTrace();
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
		//copies the input, output and expected output to outputStreams
		//if the value is too long, cut it in the middle and append ".." to sign that this is not the complete value
		String input =  value.getElement().toString();
		if (input.length()>100){
			input = input.substring(0,99)+"...";
		}
		String output = invertResult.getElement().toString();
		if (output.length()>100){
			output = output.substring(0,99)+"...";
		}
		
		//writes the result to a string
		String testResult = null;
		if (result){
			testResult = "Success: output is as expected";
		} else {
			testResult = "Failure: output is different from the expected " + input;
		}
		
		//prints the test results to the given output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Compute and invert compare,Test vector," + input + "," + output + ","+testResult);
		
	}
	
	/**
	 * Runs all the required wrong behavior tests for trapdoor permutation. 
	 * Each test can be either implemented in the derived hash test class or in this abstract class.
	 * @param file the output file
	 */
	public void wrongBehavior(PrintWriter file) {
		//call the wrong behavior functions
		unInited(file);   //case that a function is called while the object is not initialized
		wrongKeyType(file);  //case that the given key is not match the trapdoor
		wrongAlgSpec(file); //case that the given spec is not match the trapdoor
		wrongArgumentType(file); //case that the given element is not match the trapdoor
		badCasting(file);  //case that the input was casted badly
	}
	
	/**
	 * Test the case that the given key is not match the trapdoor. For example - a Rabin key was sent to RSA permutation
	 * @param file the output file
	 */
	protected abstract void wrongKeyType(PrintWriter file);
	
	/**
	 * Test the case that the given algorithmParameterSpec is not match the trapdoor. For example - a DHParameterSpec was sent to RSA permutation
	 * @param file the output file
	 */
	private void wrongAlgSpec(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//creates an DH algorithmParameterSpec, which is not trapdoor's algorithmParameterSpec
			AlgorithmParameterSpec spec = new DHParameterSpec(new BigInteger("11"), new BigInteger("3"));
			//initialized the trapdoorPermutation with the DH spec
			tp.init(spec);
			
		//the expected result of this test is InvalidParameterSpecException
		}catch(InvalidParameterSpecException e){
			testResult = "Success: The expected exception \"InvalidParameterSpecException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"InvalidParameterSpecException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Wrong algorithmParameterSpec,Wrong behavior,,," + testResult);
	}

	/**
	 * Tests the case that a function is called while the object is not initialized.
	 * the expected result is to throw UnInitializedException
	 * @param the output file
	 */
	private void unInited(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			TPElement element = tp.getRandomTPElement();
			
			//computes the function without initializes the object
			tp.compute(element);
			tp.invert(element);
			
		//the expected result of this test is UnInitializedException
		}catch(UnInitializedException e){
			testResult = "Success: The expected exception \"UnInitializedException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"UnInitializedException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",unInited,Wrong behavior,,," + testResult);
	}

	/** 
	 * Tests the case that the given argument is not match the expected argument type
	 * the expected result is to throw ClassCastException
	 * @param the output file
	 */
	private void badCasting(PrintWriter file) {
		String testResult = "Failure: no exception was thrown"; //the test result. initialized to failure
		try{
			//cast a SecretKey to PublicKey and PrivateKey
			tp.init((PublicKey) new SecretKeySpec("adsfd".getBytes(), ""), (PrivateKey) new SecretKeySpec("asdfsdf".getBytes(), ""));
			
		//the expected result of this test is ClassCastException
		}catch(ClassCastException e){
			testResult = "Success: The expected exception \"ClassCastException\" was thrown";
		//any other exception is a failure
		}catch(Exception e){
			testResult = "Failure: Exception different from the expected exception \"ClassCastException\" was thrown";
		}
		
		//prints the result to the output file
		file.println(tp.getAlgorithmName() + "," + provider + ",Bad casting,Wrong behavior,,," + testResult);		
	}
	
	/**
	 * Test the case that the given argument is not match the trapdoor. For example - a Rabin element was sent to RSA permutation
	 * @param file the output file
	 */
	protected abstract void wrongArgumentType(PrintWriter file);
		
	/**
	 * Nested TestData class, which is the data for the compute and compare test vector.
	 * It contains the input, expected output and the keys
	 *
	 */
	class TestData{
		TPElement input;
		TPElement output;
		PublicKey publicKey;
		PrivateKey privateKey;

		/**
		 * Sets the data
		 */
		public TestData(TPElement input, TPElement output, PublicKey publicKey, PrivateKey privateKey) {
			this.input = input;
			this.output = output;
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}
		
		
	}
	
	/**
	 * Nested TestData class, which is the data for the compute and invert compare test vector.
	 * It contains the input, expected output, keys and algorithmParameterSpec
	 *
	 */
	class TestDataInvertCompute{
		TPElement input;
		PublicKey publicKey;
		PrivateKey privateKey;
		AlgorithmParameterSpec spec;
		/**
		 * Constructor that gets the input and keys
		 * 
		 */
		public TestDataInvertCompute(TPElement input, PublicKey publicKey, PrivateKey privateKey) {
			this.input = input;
			this.publicKey = publicKey;
			this.privateKey = privateKey;
			spec = null;
		}
		
		/**
		 * Constructor that gets the input and algorithmParameterSpec, in case of choosing a random keys
		 * 
		 */
		public TestDataInvertCompute(TPElement input, AlgorithmParameterSpec spec) {
			this.input = input;
			this.publicKey = null;
			this.privateKey = null;
			this.spec = spec;
		}
		
		/**
		 * Constructor that gets the algorithmParameterSpec, in case of choosing a random element
		 * 
		 */
		public TestDataInvertCompute(AlgorithmParameterSpec spec) {
			this.input = null;
			this.publicKey = null;
			this.privateKey = null;
			this.spec = spec;
		}
		
		
	}

}
