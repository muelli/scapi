/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.
 * File: PlainChannel.java.
 * Creation date Feb 16, 2011
 * Create by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm;

/**
 * @author LabTest
 *
 */
public abstract class PlainChannel implements Channel {

	private State state;
	
	/**
	 * 
	 */
	public void receive(Object msg) {
		// TODO Auto-generated method stub

	}

	/**
	 * 
	 */
	public void send(Object msg) {
		// TODO Auto-generated method stub

	}

	/**
	 * returns the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	 * that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	 */
	public State getState() {
		
		return state;
	}

	/**
	 * Sets the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	 * that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	 */
	public void setState(State state) {
		this.state = state; 
		
	}

}
