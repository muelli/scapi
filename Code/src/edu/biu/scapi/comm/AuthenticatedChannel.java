/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.security.Key;

/** 
 * @author LabTest
 */
public class AuthenticatedChannel extends ChannelDecorator {
	//private DigitalSignature digitalSignature;

	Key authKey;
	
	/** 
	 * @param channel
	 * @param digSign
	 * @param setOfKeys
	 */
	AuthenticatedChannel(Channel channel/*, DigitalSignature digSign,	SetKey setOfKeys*/) {
		super(channel);	
	}
	
	AuthenticatedChannel(Channel channel, Key authKey){
		super(channel);
		this.authKey = authKey;
	}
	

	/** 
	 * @param data
	 */
	private void sign(byte[] data) {
			}

	/** 
	 * @param data
	 */
	private void verify(byte[] data) {
		
	}
	
	/**
	 * 
	 */
	public Message receive() throws ClassNotFoundException, IOException {
		
		//get the message from the channel
		Message msg = channel.receive();
		
		//unmac the authenticated message
		
		return msg;
	}

	/**
	 * 
	 */
	public void send(Message msg) throws IOException {
		
		//mac the message
		
		channel.send(msg);
		
		
	}


	
	
}