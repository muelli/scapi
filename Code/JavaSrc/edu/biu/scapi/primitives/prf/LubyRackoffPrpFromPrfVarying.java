/**
 * The class LubyRackoffPrpFromPrfVarying is one implementation that has a varying input and output length. LubyRackoffPrpFromPrfVarying is a 
 * pseudorandom permutation with varying input/output lengths, based on any PRF with a variable input/output length 
 * (as long as input length = output length). We take the interpretation that there is essentially a different random permutation
 * for every input/output length.
 */
package edu.biu.scapi.primitives.prf;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.tools.Factories.FactoriesException;
import edu.biu.scapi.tools.Factories.PrfFactory;

/** 
 * @author LabTest
 * 
 */
public final class LubyRackoffPrpFromPrfVarying extends PrpFromPrfVarying {
	
	
	public LubyRackoffPrpFromPrfVarying(String prfVaringIOLengthName) throws FactoriesException {
		
		//get the requested prpFixed from the factory. 
		prfVaryingIOLength = (PrfVaryingIOLength) PrfFactory.getInstance().getObject(prfVaringIOLengthName);
	}
	
	
	/**
	 * 
	 * @param prfFixed the underlying prf fixed. MUST be initialized.
	 */
	public LubyRackoffPrpFromPrfVarying(PrfVaryingIOLength prfVaryingIOLength){
		
		//first check that the prp fixed is initialized.
		if(prfVaryingIOLength.isInitialized()){
			//assign the prf fixed input.
			this.prfVaryingIOLength = prfVaryingIOLength;
		}
		else{//the user must pass an initialized object, otherwise throw an exception
			throw new IllegalStateException("The input variable must be initialized");
		}
		
	}
	/** 
	 * pseudocode: 
	 * Input :
	 *		 x = inBytes – should  be of even length                                                      
	 *		-----------------
	 *		Let |x|=2L (i.e., the length of the input is 2L) 
	 *		Let L0 be the first |x|/2 bits of x 
	 *		Let R0 be the second |x|/2 bits of x 
	 *		For i = 1 to 4 
	 *		SET Li = Ri-1 
     *		compute Ri = Li-1 | PRF_VARY_INOUT(k,(Ri-1,i),L)  
	 *		[key=k, data=(Ri-1,i),  outlen = L] 
	 *		return (L4,R4) 
	 *
	 * @param inBytes input bytes to compute
	 * @param inLen the length of the input array
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of compute
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param outLen the length of the output array
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException {
		
		if (inLen!=outLen){
			throw new IllegalBlockSizeException("Input and output must be of the same length");
		}
		
		//check that the input is of even length.
		if(!(inLen % 2==0) ){//odd throw exception
			throw new IllegalBlockSizeException("Length of input must be even");
		}
		
		int sideSize = inLen/2;//L in the pseudo code
		byte[] tmpReference;
		byte[] leftCurrent = new byte[sideSize];
		byte[] rightCurrent = new byte[sideSize+1];//keep space for the index. Size of L+1. 
		byte[] leftNext = new byte[sideSize];
		byte[] rightNext = new byte[sideSize+1];//keep space for the index. Size of L+1.
		
			
		//Let left_current be the first half bits of the input
		System.arraycopy(inBytes, inOff, leftCurrent, 0, sideSize);
		
		//Let right_current be the last half bits of the input
		System.arraycopy(inBytes, inOff+sideSize, rightCurrent, 0, sideSize);
		
		for(int i=1; i<=4; i++){
	
			//Li = Ri-1
			System.arraycopy(rightCurrent, 0, leftNext, 0, sideSize);
			
			//put the index in the last position of Ri-1
			rightCurrent[sideSize] = new Integer(i).byteValue();
			
			//do PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
			//put the result in the rightNext array. Later we will XOr it with leftCurrent. Note that the result size is not the entire
			//rightNext array. It is one byte less. The remaining byte will contain the index for the next iteration.
			prfVaryingIOLength.computeBlock(rightCurrent, 0, rightCurrent.length, rightNext, 0, sideSize);
			
			//do Ri = Li-1 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
			//XOR rightNext (which is the resulting prf computation by now) with leftCurrent.
			for(int j=0;j<sideSize;j++){
				
				rightNext[j] = (byte) (rightNext[j] ^ leftCurrent[j]); 
			}
			
			
			//switch between the current and the next for the next round.
			//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
			//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
			//Since both current and next will point to the same memory block and thus changing one will change the other.
			tmpReference = leftCurrent;
			leftCurrent = leftNext;
			leftNext = tmpReference;
			
			tmpReference = rightCurrent;
			rightCurrent = rightNext;
			rightNext = tmpReference;
			
		}
		
		//copy the result to the out array.
		System.arraycopy(leftCurrent, 0, outBytes, outOff, inLen/2);
		System.arraycopy(rightCurrent, 0, outBytes, outOff+inLen/2, inLen/2);
		
		
	}

	/** 
	 * Inverts the permutation using the given key. Since LubyRackoff permutation can also have varying input and output length 
	 * (although the input and the output should be the same length), the common parameter <code>len<code> of the input and the output is needed.
	 * LubyRackoff has a feistel structure and thus invert is possible even though the underlying prf is not invertible.
	 * The pseudocode for inverting such a structure is the following
	 * FOR i = 4 to 1
     * SET Ri-1 = Li 
     * COMPUTE Li-1 = Ri XOR PRF_VARY_INOUT(k,(Ri-1 (or Li),i),L)    
     *                     [key=k, data=(Ri-1,i), outlen = L]
	 *	OUTPUT (L0,R0)
	 * 
	 * @param inBytes input bytes to invert.
	 * @param inOff input offset in the inBytes array
	 * @param outBytes output bytes. The resulted bytes of invert
	 * @param outOff output offset in the outBytes array to take the result from
	 * @param len the length of the input and the output
	 * @throws IllegalBlockSizeException 
	 */
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff, int len) throws IllegalBlockSizeException {

		//check that the input is of even length.
		if(!(len % 2==0) ){//odd throw exception
			throw new IllegalBlockSizeException("Length of input must be even");
		}
		
		int sideSize = len/2;//L in the pseudo code
		byte[] tmpReference;
		byte[] leftCurrent = new byte[sideSize];
		byte[] rightCurrent = new byte[sideSize+1];//keep space for the index. Size of L+1. 
		byte[] leftNext = new byte[sideSize];
		byte[] rightNext = new byte[sideSize+1];//keep space for the index. Size of L+1.
		
			
		//Let leftNext be the first half bits of the input
		System.arraycopy(inBytes, inOff, leftNext, 0, sideSize);
		
		//Let rightNext be the last half bits of the input
		System.arraycopy(inBytes, inOff+sideSize, rightNext, 0, sideSize);
		
		for(int i=4; i>=1; i--){
			
			//Ri-1 = Li
			System.arraycopy(leftNext, 0, rightCurrent, 0, sideSize);
			
			//complete Ri-1 = Ri-1|i 
			rightCurrent[sideSize] = new Integer(i).byteValue();
			
			//do PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
			//put the result in the leftCurrent array. Later we will XOr it with rightNext. Note that the result size is not the entire
			//leftCurrent array. 
			prfVaryingIOLength.computeBlock(rightCurrent, 0, rightCurrent.length, leftCurrent, 0, sideSize);
			
			//do Ri = L0 ^ PRF_VARY_INOUT(k,(Ri-1,i),L)  
			//XOR rightNext (which is the resulting prf computation by now) with leftCurrent.
			for(int j=0;j<sideSize;j++){
				
				leftCurrent[j] = (byte) (leftCurrent[j] ^ rightNext[j]); 
			}
			
			
			//switch between the current and the next for the next round.
			//Note that it is much more readable and straightforward to copy the next arrays into the current arrays.
			//However why copy if we can switch between them and avoid the performance increase by copying. We can not just use assignment 
			//Since both current and next will point to the same memory block and thus changing one will change the other.
			tmpReference = leftNext;
			leftNext = leftCurrent;
			leftCurrent = tmpReference;
			
			tmpReference = rightNext;
			rightNext = rightCurrent;
			rightCurrent = tmpReference;
			
		}
		
		//copy the result to the out array.
		System.arraycopy(leftNext, 0, outBytes, outOff, sideSize);
		System.arraycopy(rightNext, 0, outBytes, outOff+sideSize, sideSize);
		
	}

	
	public String getAlgorithmName() {
		
		return "LUBY_RACKOFF_PRP_FROM_PRP_VARYING";
	}

	
	public int getBlockSize() {
		return 0;
	}


}