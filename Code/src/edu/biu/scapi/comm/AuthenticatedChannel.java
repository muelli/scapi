/**
 * 
 */
package edu.biu.scapi.comm;

/** 
 * @author LabTest
 */
public class AuthenticatedChannel extends ChannelDecorator {
	//private DigitalSignature digitalSignature;

	/** 
	 * @param channel
	 * @param digSign
	 * @param setOfKeys
	 */
	AuthenticatedChannel(Channel channel/*, DigitalSignature digSign,	SetKey setOfKeys*/) {
		super(channel);	
	}
	

	/** 
	 * @param data
	 */
	private void sign(byte[] data) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param data
	 */
	private void verify(byte[] data) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}


	
	
}