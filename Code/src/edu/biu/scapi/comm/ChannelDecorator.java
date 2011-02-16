/**
 * 
 */
package edu.biu.scapi.comm;

/** 
  * @author LabTest
 */
public abstract class ChannelDecorator implements Channel {
	private Channel channel;
	
	/**
	 * 
	 */
	public void receive(Object msg) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 */
	public void send(Object msg) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 * @param channel
	 */
	public ChannelDecorator(Channel channel) {
		this.channel = channel;
	}
	
}