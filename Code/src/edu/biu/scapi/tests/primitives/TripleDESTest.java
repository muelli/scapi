/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import edu.biu.scapi.primitives.crypto.prf.TripleDES;

/**
 * 
 * @author LabTest
 *
 */
public class TripleDESTest extends PrfTest {


	/**
	 * 
	 */
	public TripleDESTest(TripleDES tripleDES) {
		
		super(tripleDES);
		
		//Triple DES
		/*addData(Hex.decode("4e6f7720697320746865"),//input
				Hex.decode("d80a0d8b2bae5e4e6a00"),//output
				Hex.decode("0123456789abcdeffedcba9876543210"));//key*/
		
	}
	

	/** 
	 * 
	 */
	public void wrongKeyType() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * 
	 */
	public void wrongKeySize() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * 
	 */
	public void wrongOffset() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * 
	 */
	public void wrongAlgSpec() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 */
	public void unInited() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 */
	public void wrongKeyEncoding() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
}