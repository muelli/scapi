/**
 * 
 */
package edu.biu.scapi.primitives.crypto.prf;

import javax.crypto.IllegalBlockSizeException;

/** 
 * @author LabTest
 */
public class ScPrpFromPrfFixed extends PrpFromPrfFixed {
	
	
	/**
	 * 
	 */
	public ScPrpFromPrfFixed(String prpFixed) {

		//get the prfFixed using the factory and set it.
	}
	
	/** 
	 * @param inBytes- input bytes to compute
	 * @param inLen - the length of the input array
	 * @param inOff - input offset in the inBytes array
	 * @param outBytes - output bytes. The resulted bytes of compute.
	 * @param outOff - output offset in the outBytes array to take the result from
	 * @param outLen - the length of the output array
	 * @throws IllegalBlockSizeException 
	 * @throws IllegalBlockSizeException 
	 */
	public void computeBlock(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff, int outLen) throws IllegalBlockSizeException {
		
		//check that the input is of even length.
		if(!(inLen % 2==0) ){//odd throw exception
			throw new IllegalBlockSizeException("Length of input must be even");
		}
		else if (inLen!=outLen){
			throw new IllegalBlockSizeException("Input and output must be of the same length");
		}
		
		int sideSize = inLen/2;
		byte[] tmpReference;
		byte[] leftCurrent = new byte[sideSize];
		byte[] rightCurrent = new byte[sideSize+1];//keep space for the index
		byte[] leftNext = new byte[sideSize];
		byte[] rightNext = new byte[sideSize+1];//keep space for the index
		
			
		//Let left_current be the first half bits of the input
		System.arraycopy(inBytes, inOff, leftCurrent, 0, inLen);
		
		//Let right_current be the last half bits of the input
		System.arraycopy(inBytes, inOff+sideSize, rightCurrent, 0, inLen);
		
		for(int i=1; i<=4; i++){
			
			leftNext = rightCurrent;
			
			rightNext[sideSize] = new Integer(i).byteValue();
			
			//do PRF_VARY_INOUT(k,(Ri-1,i),L) of the pseudocode
			//put the result in the rightNext array. Later we will XOr it with leftCurrent. Note that the result size is not the entire
			//rightNext array. It is one byte less. The remaining byte will contain the index for the next iteration.
			prfFixed.computeBlock(rightCurrent, 0, rightCurrent.length, rightNext, 0, inLen);
			
			//XOR rightNext (which is the resulting prf computation by now) with leftCurrent.
			for(int j=0;j<sideSize;j++){
				
				rightNext[j] = (byte) (rightNext[j] ^ leftCurrent[j]); 
			}
			
			
			//switch between the current and the next for the next round.
			//Note that it is much more readable and straighforward to copy the next arrays into the current arrays.
			//However why copy if we can switch between them and avoid the performance increse by copying. We can not just use assignment 
			//Since both current and next will point to the same memory block and thus changing one will change the other.
			tmpReference = leftCurrent;
			leftCurrent = leftNext;
			leftNext = tmpReference;
			
			tmpReference = rightCurrent;
			rightCurrent = rightNext;
			rightNext = tmpReference;
			
		}
		
		//copy the result to the out array.
		System.arraycopy(leftNext, 0, outBytes, outOff, inLen/2);
		System.arraycopy(rightNext, 0, outBytes, outOff+inLen/2, inLen/2);
		
		/*Input :
			 x = inBytes – should  be of even length                                                      
			-----------------
			Let |x|=2L (i.e., the length of the input is 2L) 
			Let L0 be the first |x|/2 bits of x 
			Let R0 be the second |x|/2 bits of x 
			For i = 1 to 4 
			SET Li = Ri-1 
			compute Ri = L0 | PRF_VARY_INOUT(k,(Ri-1,i),L)  
			[key=k, data=(Ri-1,i),  outlen = L] 
			return (L4,R4) 
		*/


		
	}

	public void computeBlock(byte[] inBytes, int inOffset, int inLen,
			byte[] outBytes, int outOffset) throws IllegalBlockSizeException {
		// TODO Auto-generated method stub
		
	}

	
	public void invertBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {
		// TODO Auto-generated method stub
		
	}

	
	public void computeBlock(byte[] inBytes, int inOff, byte[] outBytes,
			int outOff) throws IllegalBlockSizeException {
		// TODO Auto-generated method stub
		
	}

	
	public String getAlgorithmName() {
	
		return "SC_PRP_FROM_PRP_FIXED";
	}

	
	public int getBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	
}