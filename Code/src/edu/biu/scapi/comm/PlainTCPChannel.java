/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/** 
 * @author LabTest
 */
public class PlainTCPChannel extends PlainChannel{
	private Socket socket = new Socket();
	private ObjectOutputStream outStream;
	private ObjectInputStream inStream;
	private InetSocketAddress socketAddress;

	
	/** 
	 * @param ipAddress
	 * @param port
	 */
	PlainTCPChannel(InetAddress ipAddress, int port) {
		
		socketAddress = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * 
	 */
	public PlainTCPChannel(InetSocketAddress socketAddress) {

		this.socketAddress = socketAddress;
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
		
	}

	
	
	
	/** 
	 * @param msg
	 * @throws IOException 
	 */
	public void send(Message msg) throws IOException {
		
		System.out.println("Sending " + msg.toString());
		
		outStream.writeObject(msg);
	}

	/** 
	 * @param msg
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 */
	public Message receive() throws ClassNotFoundException, IOException {
		
		System.out.println("receiving... ");
		return ((Message)inStream.readObject());
	}

	/**
	 * 
	 * close : closes the socket and the out and in streams.
	 */
	public void close() {

		if(socket!=null){
			try {
				socket.close();
				outStream.close();
				inStream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
	}

	
	/** 
	 * Connect : connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * 			 is not up yet than we sleep for a while and try again until the connection is established.
	 * 			 After the connection has succeeded the input and output streams are set for the send and receive functions.
	 * @return
	 * @throws IOException 
	 */
	boolean connect() throws IOException {
		
		//try to connect
		System.out.println("Trying to connect to " + socketAddress.getPort());
		
		//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
		socket = new Socket(socketAddress.getAddress(), socketAddress.getPort());
		//socket.connect(socketAddress,1000);
			
		
		if(socket.isConnected()){
			try {
				System.out.println("Socket connected");
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return true;
		
	}
	
	boolean isConnected(){
		
		if(socket!=null)
			return socket.isConnected();
		else
			return false;
	}

	


	/**
	 * setSocket : Sets the socket and the input and output streams. If the user uses this function it means that 
	 * 			   the connect function will not be called and thus, the streams should be set here.
	 * @param socket the socket to set
	 * 		
	 */
	void setSocket(Socket socket) {
		this.socket = socket;
		
		try {
			outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	
}