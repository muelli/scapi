/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

/** 
 * @author LabTest
 */
class ListeningThread extends Thread{
	private Map<InetAddress , Vector<SecuringConnectionThread>> connectingThreads;//map that includes only SecuringConnectionThread of the down connections
	private int port;//the port to listen on
	private boolean bStopped = false;//a flag that indicates if to keep on listening or stop
	private ServerSocketChannel listener;
	private int numOfIncomingConnections;
	

	/**
	 * 
	 */
	public ListeningThread( Map<InetAddress ,Vector<SecuringConnectionThread>> securingThreads, int port, int numOfIncomingConnections) {

		connectingThreads = securingThreads;
		this.numOfIncomingConnections = numOfIncomingConnections;
		
		//prepare the listener.
		try {
			listener = ServerSocketChannel.open();
			listener.socket().bind (new InetSocketAddress (port));
			listener.configureBlocking (false);
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		
	}
	
	/**
	 * 
	 * stopConnecting - sets the flag bStopped to false. In the run function of this thread this flag is checked
	 * 					if the flag is true the run functions returns, otherwise continues.
	 */
	public void stopConnecting(){
		
		//set the flag to true.
		bStopped = true;
	}
	
	
	
	/**
	 * run : This function is the main function of the ListeningThread. Mainly, we listen and accept valid connections as long
	 *  	 as the flag bStopped is false.
	 *       We use the ServerSocketChannel rather than the regular ServerSocket since we want the accept to be non-blocking. If
	 *       the accept function is blocking the flag bStopped will not be checked until the thread is unblocked.  
	 */
	public void run() {

		//first set the channels in the map to connecting
		/*Collection<SecuringConnectionThread> c = connectingThreads.values();
		Iterator<SecuringConnectionThread> itr = c.iterator();
		
		while(itr.hasNext()){  
			PlainChannel channel = ((SecuringConnectionThread)itr.next()).getChannel();
			
			//set the channel state to connecting
		    channel.setState(PlainChannel.State.CONNECTING);
		       
		}*/
		
		//calculate the number of incoming connections
		
		//int numOfIncomingConnections = connectingThreads.size();
			
		int i=0;
		//loop for incoming connections and make sure that this thread should not stopped.
        while (i < numOfIncomingConnections && !bStopped) {
        	
            SocketChannel socketChannel = null;
			try {
				
				//use the server socket to listen on incoming connections.
				// accept connections from all the smaller processes
				
				System.out.println("Trying to listen " + listener.socket().getLocalPort());
				socketChannel = listener.accept();
				
				//s.setTcpNoDelay(true);//consider the 2 options of nagle
				
			}	catch (ClosedChannelException e) {
				// TODO: handle exception
			} 	catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//there was no connection request
			if(socketChannel==null){
				try {
					Thread.sleep (1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else{
				
				
				//get the ip of the client socket
				InetAddress inetAddr = socketChannel.socket().getInetAddress();
				
				
				//get the address from the socket and find it the map
				Vector<SecuringConnectionThread> vectorScThreads = connectingThreads.get(inetAddr);
				
				//check if the ip address is a valid address. i.e. exists in the map
				if(vectorScThreads==null){//an un authorized ip tried to connect
					
					//close the socket
					try {
						socketChannel.close();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
	        	else{ //we have a thread that corresponds to this ip address. Thus, this address is valid
	        		
	        		//increment the index
	        		i++;
	        		
	        		//remove the first index and get the securing thread
	        		SecuringConnectionThread scThread = vectorScThreads.remove(0);
	        		
	        		//If there is nothing left in the vector remove it from the map too.
	        		if(vectorScThreads.size()==0){
	        			
	        			connectingThreads.remove(inetAddr);
	        		}
	        			
	        		
	        		//check that the channel is concrete channel and not some decoration
	        		if(scThread.getChannel() instanceof PlainTCPChannel){
	        			//get the channel from the thread and set the obtained socket.
	        			((PlainTCPChannel)scThread.getChannel()).setSocket(socketChannel.socket());
	        			
	        			//start the connecting thread
	        			scThread.start();
	        		}
	        		else
	        			;//throw an exception. The channel must be concrete
	        		
	        	}
			}
        		
        }	
        System.out.println("End of listening thread run");
	}
}