package edu.biu.scapi.primitives.dlog;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Vector;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;

/**
 * DlogGroupAbs is an abstract class that implements common functionality of the Dlog group.
 * @author Moriya
 *
 */
public abstract class DlogGroupAbs implements DlogGroup{

	protected GroupParams groupParams;			//group parameters
	protected GroupElement generator;			//generator of the group
	protected boolean isInitialized = false;	//flag if an object is initialized or not
	//map for multExponentiationsWithSameBase calculations
	private HashMap<GroupElement, GroupElementsExponentiations> exponentiationsMap = new HashMap<GroupElement, GroupElementsExponentiations>();
	
	/**
	 * 
	 * @return true if the object was initialized. Usually this means that the function init was called
	 */
	public boolean isInitialized(){
		return isInitialized;
	}
	
	/**
	 * 
	 * @return the generator of that Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupElement getGenerator() throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return generator;
	}
	
	/**
	 * 
	 * @return the GroupDesc of that Dlog group
	 * @throws UnInitializedException 
	 */
	public GroupParams getGroupParams() throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return groupParams;
	}
	
	/**
	 * 
	 * @return the order of that Dlog group
	 * @throws UnInitializedException 
	 */
	public BigInteger getOrder() throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return groupParams.getQ();
	}
	
	/**
	 * Checks if the order is a prime number
	 * @return true if the order is a prime number. false, otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isPrimeOrder() throws UnInitializedException{
		
		/* isProbablePrime is BigInteger function, which gets a certainty parameter.
		 * We will test some values to decide which is appropriate to our demands.
		 */
		if (getOrder().isProbablePrime(8))
			return true;
		else return false;
	}

	/**
	 * checks if the order is greater than 2^numBits
	 * @param numBits
	 * @return true if the order is greater than 2^numBits, false - otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isOrderGreaterThan(int numBits) throws UnInitializedException{
		if (getOrder().compareTo(new BigInteger("2").pow(numBits)) > 0)
			return true;
		else return false;
	}
	
	/**
	 * Computes the product of several exponentiations with distinct bases 
	 * and distinct exponents. 
	 * Instead of computing each part separately, an optimization is used to 
	 * compute it simultaneously. 
	 * @param groupElements
	 * @param exponentiations
	 * @return the exponentiation result
	 * @throws UnInitializedException 
	 */
	public GroupElement simultaneousMultipleExponentiations
					(GroupElement[] groupElements, BigInteger[] exponentiations) throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		/*
		 * preComputation for the algorithm.
		 */
		int preCompLen = (int) Math.pow(2, groupElements.length);
		
		GroupElement[] preComp = new GroupElement[preCompLen];
		
		/* calculates the value of each cell in the preComputation array */
		for(int k=0; k<preCompLen; k++){
			BigInteger count = new BigInteger(String.valueOf(k));
			GroupElement result = null;
			int bitCount = count.bitLength();
			//if the i bit is set, multiplies the result with the i group element
			for (int i=0; i<bitCount; i++){
				if (count.testBit(i)==true){
					if (result==null)
						result = groupElements[i];
					else 
						result = multiplyGroupElements(result, groupElements[i]);
				}
			}
			preComp[k] = result;
		}
		
		//get the biggest exponent
		BigInteger bigExp = BigInteger.ZERO;
		for (int i=0; i<exponentiations.length; i++)
			if (bigExp.compareTo(exponentiations[i])<0)
				bigExp = exponentiations[i];
		
		/*
		 * calculates the indexes array
		 */
		int t = bigExp.bitLength();
		int[] indexArr = new int[t];
		int size = exponentiations.length;
		//calculates the index of each cell in the indexes array
		for (int j=0; j<t-1; j++){
			int result = 0;
			for (int i=0; i<size; i++){
				//if the i bit is set, add to the result 2^i
				if (exponentiations[i].testBit(t-j-1)==true)
					result = (int) (result + Math.pow(2, i));
			}
			indexArr[j] = result;
		}
		
		/*
		 * calculates the multiplication result
		 */
		GroupElement a = preComp[indexArr[0]];
		
		for(int i=1; i<t; i++){
			a = multiplyGroupElements(a, a);
			if (preComp[indexArr[i]] != null)		
				a = multiplyGroupElements(a,preComp[indexArr[i]]);	
		}
		return a;
		
	}
	
	/**
	 * Computes the product of several exponentiations of the same base
	 * and distinct exponents. 
	 * An optimization is used to compute it more quickly by keeping in memory 
	 * the result of h1, h2, h4,h8,... and using it in the calculation.  
	 * @param groupElement
	 * @param exponent
	 * @return the exponentiation result
	 * @throws UnInitializedException 
	 */
	public GroupElement multExponentiationsWithSameBase
					(GroupElement groupElement, int exponent) throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//extracts from the map the GroupElementsExponentiations object corresponding to the accepted base
		GroupElementsExponentiations exponentiations = exponentiationsMap.get(groupElement);
	
		// if there is no object matches this base - creates it and add it to the map
		if (exponentiations == null){
			exponentiations = new GroupElementsExponentiations(groupElement);
			exponentiationsMap.put(groupElement, exponentiations);
		}
		//calculates the required exponent 
		return exponentiations.getExponentiation(exponent);
		
	}
	
	/**
	 * The class GroupElementExponentiations is a nested class of DlogGroupAbs.
	 * It performs the actual work of exponentially multiple exponentiations for one base.
	 * It is composed of two main elements. The group element for which the optimized computations 
	 * are built for, called the base and a vector of group elements that are the result of 
	 * exponentiations of order 1,2,4,8,… 
	 */
	private class GroupElementsExponentiations {
		private Vector<GroupElement> exponentiations; //vector of group elements that are the result of exponentiations
		private GroupElement base;  //group element for which the optimized computations are built for
		
		/**
		 * The constructor creates a map structure in memory. 
		 * Then calculates the exponentiations of order 1,2,4,8 for the given base and save them in the map.
		 * @param base
		 * @throws UnInitializedException 
		 * @throws IllegalArgumentException 
		 */
		public GroupElementsExponentiations(GroupElement base) {
			this.base = base; 
			//build new vactor of exponentiations
			exponentiations = new Vector<GroupElement>();
			exponentiations.add(0, base); //add the base - base^1
			for (int i=1; i<4; i++){
				GroupElement multI;
				try {
					multI = exponentiate(new BigInteger("2"), exponentiations.get(i-1));
					
					exponentiations.add(i, multI);
				} catch (UnInitializedException e) {
					//the creation of GroupElementsExponentiations is done after we check that the object is initialized
				}
			}
		}
		
		/**
		 * Calculates the necessary additional exponentiations and fills the exponentiations vector with them.
		 * @param size - the required exponent
		 * @throws UnInitializedException 
		 * @throws IllegalArgumentException 
		 */
		private void prepareExponentiations(int size) {
			//find the the closest power 2 exponent 
			double log = Math.log10(size)/Math.log10(2); //log_2(size)
			int index = (int) Math.floor(log); 
			
			/* calculates the necessary exponentiations and put them in the exponentiations vector */
			for (int i=exponentiations.size(); i<=index; i++){
				GroupElement multI;
				try {
					multI = exponentiate(new BigInteger("2"), exponentiations.get(i-1));
					
					exponentiations.add(i, multI);
				} catch (UnInitializedException e) {
					//the creation of GroupElementsExponentiations is done after we check that the object is initialized
				}	
			}
		}
		
		
		/**
		 * Checks if the exponentiations had already been calculated for the required size. 
		 * If so, returns them, else it calls the private function prepareExponentiations with the given size.
		 * @param size - the required exponent
		 * @return groupElement - the exponentiate result
		 */
		public GroupElement getExponentiation(int size) {
			/**
			 * The exponents in the exponents vector are all power of 2.
			 * In order to achieve the exponent size, we calculate its closest power 2 in the exponents vector 
			 * and continue the calculations from there.
			 */
			//find the the closest power 2 exponent 
			double log = Math.log10(size)/Math.log10(2); //log_2(size)
			int index = (int) Math.floor(log); 
			
			GroupElement exponent = null;
			/* if the requested index out of the vector bounds, the exponents have not been calculated yet, so calculates them.*/
			if (exponentiations.size()<= index)
				prepareExponentiations(size);
			
			exponent = exponentiations.get(index); //get the closest exponent in the exponentiations vector
			/* if size is not power 2, calculates the additional multiplications */
			if ((double) index != log){
				for (int i=(int) Math.pow(2, index); i<size; i++){
					try {
						exponent = multiplyGroupElements(base, exponent);
					} catch (UnInitializedException e) {
						//the creation of GroupElementsExponentiations is done after we check that the object is initialized
					}
				}
			}
			return exponent;		
		}
	}
	
	
}
