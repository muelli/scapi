/**
 * Project: scapi.
 * Package: edu.biu.scapi.tests.
 * File: UnitTests.java.
 * Creation date Apr 11, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.tests;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.dlog.DlogECFp;
import edu.biu.scapi.primitives.dlog.DlogEllipticCurve;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.groupParams.ECF2mGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ECFpGroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * @author LabTest
 *
 */
public class UnitTests {

	
	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {
		
		/*byte[] in = {1,2};
		CryptoPpSHA1 sha1 = new CryptoPpSHA1();
		
		String str = sha1.getAlgorithmName();
		
		
		sha1.update(in, 0, 2); 
		
		System.out.println(str);
		*/
		//correctionTest();
		//loadSimultaneousMultipleExponentiationsTest();
		loadExponentiateWithPreComputedValuesTest();
	}
	
	
	public static void loadSimultaneousMultipleExponentiationsTest(){
		BufferedReader bf;
		//read the load test data from a config file
		try {
			bf = new BufferedReader(new FileReader("C:\\development\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\tests\\DlogUnitTestConfig.txt"));
			String line;
			String[] tokens;
			String dlogGroup = null;
			String dlogProvider = null;
			String initParams = null;
			int numOfElements = 0;
			int count = 0;
			//prepare an output file
			PrintWriter out = new PrintWriter("C:\\development\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\tests\\testResults.csv");
			out.println("dlogGroup,dlogProvide,initParams,numOfElements,SimultaneousComputationTime,naiveComputationTime");
			out.flush();
			
			//read each line of the config file and set the data
			while ((line = bf.readLine()) != null) {
				 System.out.println(line);
				if (line.startsWith("DlogGroup")) {
					tokens = line.split("=");
					dlogGroup = tokens[1].trim();
				} else if (line.startsWith("DlogProvider")) {
					tokens = line.split("=");
					dlogProvider = tokens[1].trim();
				} else if (line.startsWith("InitParams")) {
					tokens = line.split("=");
					initParams = tokens[1].trim();
				} if (line.startsWith("NumOfElements")) {
					tokens = line.split("=");
					String tok = tokens[1].trim();
					numOfElements = new Integer(tok).intValue();
				}
				count++;
				//after we read one test data, compute the test
				if (count == 4) {
					compute(dlogGroup, dlogProvider, initParams, numOfElements, out);
					count = 0;
				}
			}
			out.close();
			
			
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void loadExponentiateWithPreComputedValuesTest(){
		BufferedReader bf;
		//read the load test data from a config file
		try {
			bf = new BufferedReader(new FileReader("C:\\development\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\tests\\DlogUnitTestConfig_exponentiateWithPreComp.txt"));
			String line;
			String[] tokens;
			String dlogGroup = null;
			String dlogProvider = null;
			String initParams = null;
			int iterations = 0;
			int count = 0;
			//prepare an output file
			PrintWriter out = new PrintWriter("C:\\development\\SDK\\Code\\JavaSrc\\edu\\biu\\scapi\\tests\\exponentiateWithPreComputedValuesTestResults.csv");
			out.println("dlogGroup,dlogProvide,initParams,num iterations,ExponentiateWithPreComputedValuesTime,naiveComputationTime");
			out.flush();
			
			//read each line of the config file and set the data
			while ((line = bf.readLine()) != null) {
				 System.out.println(line);
				if (line.startsWith("DlogGroup")) {
					tokens = line.split("=");
					dlogGroup = tokens[1].trim();
				} else if (line.startsWith("DlogProvider")) {
					tokens = line.split("=");
					dlogProvider = tokens[1].trim();
				} else if (line.startsWith("InitParams")) {
					tokens = line.split("=");
					initParams = tokens[1].trim();
				} else if (line.startsWith("IterationsNum")) {
					tokens = line.split("=");
					String tok = tokens[1].trim();
					iterations = new Integer(tok).intValue();
				} 
				
				count++;
				//after we read one test data, compute the test
				if (count == 4) {
					computeExponentiationWitPreComputedValues(dlogGroup, dlogProvider, initParams, iterations, out);
					count = 0;
				}
			}
			out.close();
			
			
			
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private static void compute(String dlogGroup, String dlogProvider, String initParams, int numOfElements, PrintWriter out){
		DlogGroup dlog;
		try {
			//create the dlog via the dlog factory using the dlog name and provider name
			dlog = DlogGroupFactory.getInstance().getObject(dlogGroup+"("+initParams+")", dlogProvider);
			BigInteger max;
			//init the dlog. there is a difference between EC groups and Zp group.
			if(dlog instanceof DlogEllipticCurve){
				if (dlog instanceof DlogECFp){
					max = ((ECFpGroupParams) dlog.getGroupParams()).getP();
				} else {
					max = new BigInteger("2").pow(((ECF2mGroupParams) dlog.getGroupParams()).getM());
				}
			}
			else{
				max = ((ZpGroupParams) dlog.getGroupParams()).getP();
			}
			SecureRandom random = new SecureRandom();
			BigInteger[] exponents = new BigInteger[numOfElements];
			
			Date start = new Date();
			//after we know the number of elements, create an exponents array in this size and fill it with random BigIntegers
			for (int i=0; i<numOfElements; i++){
				exponents[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, max, random);
			}
			Date end = new Date();
			long time = (end.getTime() - start.getTime());
			System.out.println("create random exponents took "+time + " milis");
			//create an elements array and fill it with random elements
			GroupElement[] groupElements = new GroupElement[numOfElements];
			start = new Date();
			for (int i=0; i<numOfElements; i++){
				groupElements[i] = dlog.getRandomElement();
			}
			end = new Date();
			time = (end.getTime() - start.getTime());
			System.out.println("create random elements took "+ time + " milis");
			
			//operate the simultaneous multiple exponentiation via the optimization function and calculate the computation time 
			Date startCompute = new Date();
			GroupElement simultaneousResult = dlog.simultaneousMultipleExponentiations(groupElements, exponents);
			Date endCompute = new Date();
			
			long computeSimultaneousTime = (endCompute.getTime() - startCompute.getTime());
			System.out.println("simultaneous succedded in "+ computeSimultaneousTime + " milis");
			
			//operate the simultaneous multiple exponentiation via the naive way and calculate the computation time 
			startCompute = new Date();
			//create the exponentiation array and gut in index i the result of element[i]^exponen[i]
			GroupElement[] exponentiations = new GroupElement[numOfElements];
			for (int i=0; i<numOfElements; i++){
				exponentiations[i] = dlog.exponentiate(groupElements[i], exponents[i]);
			}
			//calculate the multiplication of all the exponentiations
			GroupElement multiplicationResult = exponentiations[0];
			for (int i=1; i<numOfElements; i++){
				multiplicationResult = dlog.multiplyGroupElements(multiplicationResult, exponentiations[i]);
			}
			endCompute = new Date();
			
			long computeNaiveTime = (endCompute.getTime() - startCompute.getTime());
			System.out.println("naive computation succedded in "+ computeNaiveTime + " milis");
			
			//check if the optimization result and the naive result are the same
			if (simultaneousResult.equals(multiplicationResult)){
				System.out.println("naive result and simultaneous are equal!");
			} else{
				System.out.println("error!!!!! naive result and simultaneous are not equal!");
			}
			//write the output to the output file
			String str = dlogGroup + "," + dlogProvider + "," + initParams + "," + numOfElements +"," + computeSimultaneousTime + "," + computeNaiveTime;
			out.println(str);
			out.flush();
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}

	private static void computeExponentiationWitPreComputedValues(String dlogGroup, String dlogProvider, String initParams, int iterations, PrintWriter out){
		DlogGroup dlog;
		try {
			//create the dlog via the dlog factory using the dlog name and provider name
			dlog = DlogGroupFactory.getInstance().getObject(dlogGroup+"("+initParams+")", dlogProvider);
			//init the dlog. there is a difference between EC groups and Zp group.
			
			
			SecureRandom random = new SecureRandom();
			BigInteger exponent = BigIntegers.createRandomInRange(BigInteger.ONE, dlog.getOrder(), random);
			//create an elements array and fill it with random elements
			GroupElement groupElement = dlog.getRandomElement();
			BigInteger seven = new BigInteger("7");
			GroupElement preComputedResult = null;
			GroupElement naiveResult = null;
			BigInteger temp = exponent;
			
			Date startCompute = new Date();
			for(int i=0; i<iterations; i++){
				
				//operate the exponentiate via the optimization function and calculate the computation time 
				preComputedResult = dlog.exponentiateWithPreComputedValues(groupElement, exponent);
				exponent = exponent.multiply(seven).mod(dlog.getOrder());
				
			}
			
			Date endCompute = new Date();
			long computeExponentiateTime = (endCompute.getTime() - startCompute.getTime());
			System.out.println("exponentiate with pre computd values succedded in "+ computeExponentiateTime + " milis");
			
			exponent = temp;
			//operate the exponentiate via the naive way and calculate the computation time 
			startCompute = new Date();
			for(int i=0; i<iterations; i++){
				naiveResult = dlog.exponentiate(groupElement, exponent);
				exponent = exponent.multiply(seven).mod(dlog.getOrder());
				
			}
			
			endCompute = new Date();
			long computeNaiveTime = (endCompute.getTime() - startCompute.getTime());
			System.out.println("naive computation succedded in "+ computeNaiveTime + " milis");
			
			//check if the optimization result and the naive result are the same
			if (preComputedResult.equals(naiveResult)){
				System.out.println("naive result and simultaneous are equal!");
			} else{
				System.out.println("error!!!!! naive result and simultaneous are not equal!");
			}
			//write the output to the output file
			String str = dlogGroup + "," + dlogProvider + "," + initParams + "," + iterations +"," + computeExponentiateTime + "," + computeNaiveTime;
			out.println(str);
			out.flush();
			
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
}
