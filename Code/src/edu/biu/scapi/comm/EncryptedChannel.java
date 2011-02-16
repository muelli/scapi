/**
 * 
 */
package edu.biu.scapi.comm;

import java.security.Key;

/** 
 * @author LabTest
 */
public class EncryptedChannel extends ChannelDecorator {
	private Key key;
	//private EncryptionAlgorithm encryptionAlgo; ?????
	private String algName;

	/** 
	 * @param channel
	 * @param algName
	 * @param setOfKeys
	 */
	EncryptedChannel(Channel channel, String algName/*, SetKey setOfKeys*/) {
		super(channel);
	}

	/** 
	 * @param data
	 */
	private void encrypt(byte[] data) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param data
	 */
	private void decrypt(byte[] data) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}
}