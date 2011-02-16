/**
 * 
 */
package edu.biu.scapi.comm;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/** 
 * @author LabTest
 */
public class PlainTCPChannel extends PlainChannel{
	private Socket socket;
	private State state;

	/** 
	 * @param msg
	 */
	public void send(Object msg) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param msg
	 */
	public void receive(Object msg) {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/**
	 * 
	 * close
	 */
	public void close() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
	}

	/** 
	 * @param ipAddress
	 * @param port
	 */
	PlainTCPChannel(InetAddress ipAddress, int port) {
		// begin-user-code
		// TODO Auto-generated constructor stub
		// end-user-code
	}
	
	/**
	 * 
	 */
	public PlainTCPChannel(InetSocketAddress address) {
		// TODO Auto-generated constructor stub
	}

	/** 
	 * @param existingChannel
	 */
	PlainTCPChannel(Channel existingChannel) {
		// begin-user-code
		// TODO Auto-generated constructor stub
		// end-user-code
	}

	/** 
	 * @param ipAddress
	 * @param port
	 * @param typeOfConnection
	 */
	PlainTCPChannel(InetAddress ipAddress, int port, Object typeOfConnection) {
		// begin-user-code
		// TODO Auto-generated constructor stub
		// end-user-code
	}

	/** 
	 * @return
	 */
	boolean connect() {
		// begin-user-code
		// TODO Auto-generated method stub
		return false;
		// end-user-code
	}

	/**
	 * 
	 */
	public void run() {
		// begin-user-code
		// TODO Auto-generated method stub

		// end-user-code
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

	/**
	 * @param socket the socket to set
	 */
	public void setSocket(Socket socket) {
		this.socket = socket;
	}

	
}