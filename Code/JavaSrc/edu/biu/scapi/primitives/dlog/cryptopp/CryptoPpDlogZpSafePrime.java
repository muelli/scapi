package edu.biu.scapi.primitives.dlog.cryptopp;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import edu.biu.scapi.exceptions.UnInitializedException;
import edu.biu.scapi.primitives.dlog.DlogGroupAbs;
import edu.biu.scapi.primitives.dlog.DlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.ZpElement;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.securityLevel.DDH;

/**This class implements a Dlog group over Zp* utilizing Crypto++'s implementation.<p>
 * It uses JNI technology to call Crypto++'s native code.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 */
public class CryptoPpDlogZpSafePrime extends DlogGroupAbs implements DlogZpSafePrime, DDH{

	private long pointerToGroup = 0; //pointer to the native group object
	
	/* native functions for the Dlog functionality*/
	private native long createDlogZp(byte[] p, byte[]q, byte[] g);
	private native long createRandomDlogZp(int numBits);
	private native long getGenerator(long group);
	private native byte[] getP(long group);
	private native byte[] getQ(long group);
	private native long inverseElement(long group, long element);
	private native long exponentiateElement(long group, long element, byte[] exponent);
	private native long multiplyElements(long group, long element1, long element2);
	private native void deleteDlogZp(long group);
	private native boolean validateZpGroup(long group);
	private native boolean validateZpGenerator(long group);
	private native boolean validateZpElement(long group, long element);
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with the given groupParams
	 * @param groupParams - contains the group parameters
	 */
	public void init(AlgorithmParameterSpec params){
		if (!(params instanceof ZpGroupParams)){
			throw new IllegalArgumentException("params should be instance of ZpGroupParams");
		}
		ZpGroupParams groupParams = (ZpGroupParams) params;
		BigInteger p = groupParams.getP();
		BigInteger q = groupParams.getQ();
		BigInteger g = groupParams.getXg();
		
		// if p is not 2q+1 throw exception
		if (!q.multiply(new BigInteger("2")).add(BigInteger.ONE).equals(p)){
			throw new IllegalArgumentException("p must be equal to 2q+1");
		}
		//if p is not a prime throw exception
		if (!p.isProbablePrime(40)){
			throw new IllegalArgumentException("p must be a prime");
		}
		//if q is not a prime throw exception
		if (!q.isProbablePrime(40)){
			throw new IllegalArgumentException("q must be a prime");
		}
		//set the inner parameters
		this.groupParams = groupParams;
		
		/* create CryptoPP Dlog group with p, ,q , g.
		 * The validity of g will be checked after the creation of the group because the check need the pointer to the group
		 */
		pointerToGroup = createDlogZp(p.toByteArray(), q.toByteArray(), g.toByteArray());
		
		/* if the generator is not valid, delete the allocated memory and throw exception */
		if (!validateZpGenerator(pointerToGroup)){
			deleteDlogZp(pointerToGroup);
			throw new IllegalArgumentException("generator value is not valid");
		}
		//create the GroupElement - generator with the pointer that return from the native function
		generator = new ZpSafePrimeElementCryptoPp(g, p, false);
		
		isInitialized = true;
	}
	
	/**
	 * Initializes the CryptoPP implementation of Dlog over Zp* with random elements
	 * @param numBits - number of the prime p bits to generate
	 */
	public void init(int numBits){
		
		//create random Zp dlog group 
		pointerToGroup = createRandomDlogZp(numBits);
		
		//get the generator value
		long pGenerator = getGenerator(pointerToGroup);
		//create the GroupElement - generator with the pointer that return from the native function
		generator = new ZpSafePrimeElementCryptoPp(pGenerator);
		
		BigInteger p = new BigInteger(getP(pointerToGroup));
		BigInteger q = new BigInteger(getQ(pointerToGroup));
		BigInteger xG = ((ZpElement) generator).getElementValue();
		
		groupParams = new ZpGroupParams(q, xG, p);
		
		isInitialized = true;
	}
	
	/**
	 * @return the type of the group - Zp*
	 */
	public String getGroupType(){
		return "Zp*";
	}
	
	/**
	 * 
	 * @return the identity of this Zp group - 1
	 * @throws UnInitializedException 
	 */
	public GroupElement getIdentity() throws UnInitializedException {
		return new ZpSafePrimeElementCryptoPp(BigInteger.ONE, ((ZpGroupParams) groupParams).getP(), false);
	}
	/**
	 * Checks if the given element is member of this Dlog group
	 * @param element 
	 * @return true if the given element is member of that group. false, otherwise.
	 * @throws UnInitializedException 
	 * @throws IllegalArgumentException
	 */
	public boolean isMember(GroupElement element) throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//check if element is ZpElementCryptoPp
		if (!(element instanceof ZpSafePrimeElementCryptoPp)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		
		return validateZpElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) element).getPointerToElement());
		
	}

	/**
	 * Checks if the given generator is indeed the generator of the group
	 * @return true, is the generator is valid, false otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean isGenerator() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return validateZpGenerator(pointerToGroup);
	}

	/**
	 * Checks if the parameters of the group are correct.
	 * @return true if valid, false otherwise.
	 * @throws UnInitializedException 
	 */
	public boolean validateGroup() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return validateZpGroup(pointerToGroup);
	}

	/**
	 * Calculates the inverse of the given GroupElement
	 * @param groupElement to inverse
	 * @return the inverse element of the given GroupElement
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement getInverse(GroupElement groupElement) throws IllegalArgumentException, UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		if (groupElement instanceof ZpSafePrimeElementCryptoPp){
			//call to native inverse function
			long invertVal = inverseElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) groupElement).getPointerToElement());
			
			//build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp inverseElement = new ZpSafePrimeElementCryptoPp(invertVal);
			
			return inverseElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Raises the base GroupElement to the exponent. The result is another GroupElement.
	 * @param exponent
	 * @param base 
	 * @return the result of the exponentiation
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement exponentiate(GroupElement base, BigInteger exponent) throws IllegalArgumentException, UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		if (base instanceof ZpSafePrimeElementCryptoPp){
			//call to native exponentiate function
			long exponentiateVal = exponentiateElement(pointerToGroup, ((ZpSafePrimeElementCryptoPp) base).getPointerToElement(), exponent.toByteArray());
			
			//build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp exponentiateElement = new ZpSafePrimeElementCryptoPp(exponentiateVal);
			
			return exponentiateElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	/**
	 * Multiplies two GroupElements
	 * @param groupElement1
	 * @param groupElement2
	 * @return the multiplication result
	 * @throws IllegalArgumentException
	 * @throws UnInitializedException 
	 */
	public GroupElement multiplyGroupElements(GroupElement groupElement1,
			GroupElement groupElement2) throws IllegalArgumentException, UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		if ((groupElement1 instanceof ZpSafePrimeElementCryptoPp) && (groupElement2 instanceof ZpSafePrimeElementCryptoPp)){
			//call to native multiply function
			long mulVal = multiplyElements(pointerToGroup, ((ZpSafePrimeElementCryptoPp) groupElement1).getPointerToElement(), 
										  ((ZpSafePrimeElementCryptoPp) groupElement2).getPointerToElement());
			
			//build a ZpElementCryptoPp element from the result value
			ZpSafePrimeElementCryptoPp mulElement = new ZpSafePrimeElementCryptoPp(mulVal);
			
			return mulElement;
			
		}else throw new IllegalArgumentException("element type doesn't match the group type");
	}

	public GroupElement simultaneousMultipleExponentiations
				(GroupElement[] groupElements, BigInteger[] exponentiations) throws UnInitializedException{
		
		if (!isInitialized()){
		throw new UnInitializedException();
		}
		
		//currently, in cryptoPpDlogZpSafePrime the native algorithm is faster than the optimized one due to many calls to the JNI.
		//Thus, we operate the native algorithm. In the future we may change this.
		return computeNaive(groupElements, exponentiations);		
		
	}
	
	/**
	 * Creates a random member of this Dlog group
	 * @return the random element
	 * @throws UnInitializedException 
	 */
	public GroupElement getRandomElement() throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return new ZpSafePrimeElementCryptoPp(((ZpGroupParams) groupParams).getP());
	}
	
	/**
	 * Creates a Zp element with the given parameter
	 * @return the created element
	 * @throws UnInitializedException 
	 */
	public ZpElement getElement(BigInteger x, Boolean bCheckMembership) throws UnInitializedException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		return new ZpSafePrimeElementCryptoPp(x, ((ZpGroupParams) groupParams).getP(), bCheckMembership);
	}
	
	/**
	 * Converts a byte array to a ZpSafePrimeElementCryptoPp element.
	 * @param binaryString the byte array to convert
	 * @return the created group Element
	 * @throws UnInitializedException 
	 */
	public GroupElement convertByteArrayToGroupElement(byte[] binaryString) throws UnInitializedException{
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		if (binaryString.length >= ((ZpGroupParams) groupParams).getP().bitLength()){
			throw new IllegalArgumentException("String is too long. It has to be of length less than p");
		}
		try{
			BigInteger elValue = new BigInteger(binaryString);
			GroupElement element= new ZpSafePrimeElementCryptoPp(elValue, ((ZpGroupParams) groupParams).getP(), true);
			return element;
		} catch(IllegalArgumentException e){
			throw new IllegalArgumentException("The given string is not a valid Zp safe prime element");
		}
	}
	
	/**
	 * Convert a ZpSafePrimeElementCryptoPp to a byte array.
	 * @param groupElement the element to convert
	 * @return the created byte array
	 */
	public byte[] convertGroupElementToByteArray(GroupElement groupElement){
		if (!(groupElement instanceof ZpSafePrimeElementCryptoPp)){
			throw new IllegalArgumentException("element type doesn't match the group type");
		}
		return ((ZpElement) groupElement).getElementValue().toByteArray();
	}
	
	/**
	 * deletes the related Dlog group object
	 */
	protected void finalize() throws Throwable {
		
		//delete from the dll the dynamic allocation of the Integer.
		deleteDlogZp(pointerToGroup);
		
		super.finalize();
	}
	
	//upload CryptoPP library
	 static {
	        System.loadLibrary("CryptoPPJavaInterface");
	 }

}
