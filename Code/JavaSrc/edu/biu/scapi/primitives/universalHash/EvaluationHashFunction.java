package edu.biu.scapi.primitives.universalHash;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.UnInitializedException;

/** 
 * Concrete class of perfect universal hash for evaluation hash function.
 * 
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class EvaluationHashFunction extends UniversalHashAbs {
	
	protected long evalHashPtr; // pointer to the native evaluation object
	
	//native functions. These functions are implemented in the NTLJavaInterface dll using the JNI
	
	//creates the native object and initializes it with the secret key
	private native long initHash(byte[] key, long keyOffset);
	//computes the evaluation hash function
	//we don't send the input offset because we always send the padded array which the offset is always 0 
	private native void computeFunction(long evalHashPtr, byte[] in, byte[] out, int outOffset);
	
	
	
	public void init(SecretKey secretKey) {

		//passes the key to the native function, which creates a native evaluation hash function instance.
		//the return value is the pointer to this instance, which we set to the class member evalHashPtr
		evalHashPtr = initHash(secretKey.getEncoded(), 0);
		
		//sets the key
		super.init(secretKey);
	}
	
	/**
	 * Evaluation hash function can get any input size which is between 0 to 64t bits. while t = 2^24.
	 * @return the upper bound of the input size - 64t
	 */
	public int getInputSize() {
		//limit = t = 2^24
		int limit = (int) Math.pow(2, 24);
		//limit = 8t, which is 64t bits in bytes
		limit = limit * 8;
		//save maximum 8 byte to the padding
		limit = limit - 8;
		return limit;
	}

	/** 
	 * @return the output size of evaluation hash function - 64 bits
	 */
	public int getOutputSize() {
		
		//64 bits long
		return 8;
	}

	/**
	 * @return the algorithm name - Evaluation Hash Function
	 */
	public String getAlgorithmName() {
		
		return "Evaluation Hash Function";
		
	}

	
	public void compute(byte[] in, int inOffset, int inLen, byte[] out,
			int outOffset) throws UnInitializedException, IllegalBlockSizeException {
		if (!isInitialized()){
			throw new UnInitializedException();
		}
		//checks that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+inLen> in.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		if ((outOffset > out.length) || (outOffset+getOutputSize() > out.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		
		//checks that the input length is not greater than the upper limit
		if(inLen > getInputSize()){
			throw new IllegalBlockSizeException("input length must be less than 64*(2^24-1) bits long");
		}
		
		byte[] padding = null;
		//pad the input.
		if ((inLen%8) == 0){
			//the input is aligned to 64 bits so pads it as aligned array
			padding = padAlignedArray(in, inOffset, inLen);
		} else {
			//the input is not aligned to 64 bits so pads it to aligned array
			padding = padNotAlignedArray(in, inOffset, inLen);
		}
		//calls the native function compute on the padded array.
		computeFunction(evalHashPtr, padding, out, outOffset);
	}
	
	/**
	 * This padding is used to get an array aligned to 8 bytes (64 bits).
	 * The padding is done by adding 10...0 until we get the number of the required bytes.
	 * The input for this function is an array of size that is not aligned to 8 bytes.
	 * @param input the input to pad. 
	 * @param offset the offset to take the input bytes from
	 * @param length the length of the input. This length is not aligned to 8 bytes.
	 * @return the aligned array
	 */
	private byte[] padNotAlignedArray(byte[] input, int offset, int length){
		//gets the number of bytes to add in order to get an aligned array
		int inputSizeMod8 = length % 8;
		int leftToAlign = 8 - inputSizeMod8;
		
		//creates an array of aligned size
		byte[] alignedInput = new byte[length+leftToAlign];
		
		//copies the given input to the beginning of the aligned array
		System.arraycopy(input, offset, alignedInput, 0, length);
		//adds the first byte of the padding the byte that represent the number 1
		Integer one = new Integer(1);
		alignedInput[length] = one.byteValue();
		
		//decreases the number of bytes left to align
		leftToAlign--;
		
		//adds zero bytes until reaches the required bytes 
		Integer zero = new Integer(0);
		for(int i=0; i<leftToAlign; i++){
			alignedInput[length+1+i] = zero.byteValue();
		}
		return alignedInput;
	}
	
	/**
	 * All the inputs for the compute function need a padding. 
	 * If the input is already aligned, the padding adds to it 8 bytes (64 bits) - 10000000.
	 * @param input the input to pad. 
	 * @param offset the offset to take the input bytes from
	 * @param length the length of the input. This length is aligned to 8 bytes.
	 * @return the aligned array
	 */
	private byte[] padAlignedArray(byte[] input, int offset, int length){

		//creates an array of input size + 8 bytes to the padding
		byte[] alignedInput = new byte[length+8];
		
		//copies the given input to the beginning of the aligned array
		System.arraycopy(input, offset, alignedInput, 0, length);
		//adds the first byte of the padding the byte that represent the number 1
		Integer one = new Integer(1);
		alignedInput[length] = one.byteValue();
		
		//adds zero bytes until reaches the required bytes 
		Integer zero = new Integer(0);
		for(int i=0; i<7; i++){
			alignedInput[length+1+i] = zero.byteValue();
		}
		return alignedInput;
	}
	
 static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	 }
}