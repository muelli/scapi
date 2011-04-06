/**
 * 
 */
package edu.biu.scapi.tests.primitives;

import org.bouncycastle.util.encoders.Hex;

import edu.biu.scapi.primitives.crypto.prf.Hmac;

/**
 * @author LabTest
 *
 * This class tests the performance and correctness of any implemented AES algorithm.
 * The test vectors are taken from hhttp://datatracker.ietf.org/doc/rfc4231/?include_text=1
 *
 */
public class HmacTest extends PrfTest {
	
	public HmacTest(Hmac hmac) {
		super(hmac);
		
		//HMAC/SHA224
		if(hmac.getBlockSize()==28)
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key

		
		//HMAC/SHA256
		if(hmac.getBlockSize()==32)
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key

		//HMAC/SHA384
		if(hmac.getBlockSize()==48)
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key
		
		
		//HMAC/SHA512
		if(hmac.getBlockSize()==64)
			addData(Hex.decode("4869205468657265"),//input
					Hex.decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),//output
					Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));//key

	}
	
	
	

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void wrongKeyType() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void wrongKeySize() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void wrongOffset() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void wrongAlgSpec() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void unInited() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * <!-- begin-UML-doc -->
	 * <!-- end-UML-doc -->
	 * @generated "UML to Java (com.ibm.xtools.transform.uml2.java5.internal.UML2JavaTransform)"
	 */
	public void wrongKeyEncoding() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
}