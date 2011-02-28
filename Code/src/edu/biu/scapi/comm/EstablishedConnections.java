/**
 * The CommunicationSetup class holds a container of type EstablishedConnections that keeps track of the connections (channels) 
 * as they are being established. This container has a number of channels that can be in different states.
 * EstablishedConnections has regular operations of containers such as add and remove. It also has logical operations such as areAllConnected.
 * At the end of the “prepare for communication” method, the calling application receives a map of connections in the EstablishedConnections 
 * object held by the CommunicationSetup. At this stage, all the channels in EstablishedConnections object need to be in READY state. 
 * It is possible that this object will be null if the “prepare for communication” did not succeed. 
 * The key to the map is an object of type InetSocketAddress that holds the IP and the port. Since the IP and port are unique, 
 * they define a unique InetSocketAddress that can serve as a key to the map.   
 */
package edu.biu.scapi.comm;

import edu.biu.scapi.comm.Channel;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/** 
 * @author LabTest
  */
public class EstablishedConnections {
	private Map<InetSocketAddress,Channel> connections;
	//private Set<Channel> channels;

	
	/**
	 * 
	 */
	public EstablishedConnections() {
		//initiate the map
		connections = new HashMap<InetSocketAddress,Channel>();
	}
	


	/**
	 * @return the connections
	 */
	public Map<InetSocketAddress,Channel> getConnections() {
		return connections;
	}
	
	/** 
	 * addConnection - adds a channel with the address key to the map
	 * @param connection - the value/channel to insert to the map
	 * @param address - the key in the map
	 */
	void addConnection(InetSocketAddress address, Channel connection) {

		// add the channel to the map
		connections.put(address, connection);
	}

	/** 
	 * removeConnection - removes a channel from the map.
	 * @param address - the key of the channel in the map
	 */
	Channel removeConnection(InetSocketAddress address) {
		
		//remove the connection
		return connections.remove(address);
	}

	/** 
	 * getConnection - gets a channel from the map.
	 * @param address - the key of the channel in the map
	 */
	Channel getConnection(InetSocketAddress address) {
		
		//remove the connection
		return connections.get(address);
	}

	
	/** 
	 * @return - the number of channels in the map
	 */
	int getConnectionsCount() {
		
		return connections.size();
	}

	/** 
	 * @return - true if all the channels are in READY state, false otherwise.
	 */
	boolean areAllConnected() {

		//set an iterator for the connection map.
		Collection<Channel> c = connections.values();
		Iterator<Channel> itr = c.iterator();
		
		PlainChannel plainChannel;
		//go over the map and check if all the connections are in READY state
		while(itr.hasNext()){
			plainChannel = (PlainChannel)itr.next();
		       if(plainChannel.getState()!=PlainChannel.State.READY){
		    	   return false;
		       }
		}
		
		return true;
	}

	/** 
	 * updateConnectionState - updates a channel state to a new state
	 * @param address - the key in the map
	 * @param state - the state of the channel to update to.
	 */
	void updateConnectionState(InetSocketAddress address, PlainChannel.State state) {

		//get the channel from the map
		Channel ch = connections.get(address);
		
		if(ch instanceof PlainChannel){
			PlainChannel plainChannel = (PlainChannel)ch;
		
			plainChannel.setState(state);
		}
		else
			;//throw exception
	}
	
	/**
	 * 
	 * removeNotReadyConnections : Removes all the connections which are not in READY state.
	 * 
	 * Note						 : Since we cannot remove connections in the middle of iterations we will create a temporary map with only the 
	 * 							   connections in READY state. At last we will remove all the connections and add only those with READY state.
	 */
	void removeNotReadyConnections(){
		
		PlainChannel plainChannel;
		InetSocketAddress address;
		
		//create a temp map since if we change the main map in the middle of iterations we will get the exception ConcurrentModificationException 
		//Map<InetSocketAddress,Channel> tempConnections = new HashMap<InetSocketAddress,Channel>();  
		
		
		//set an iterator for the connection map.
		Iterator<InetSocketAddress> iterator = connections.keySet().iterator();
		
		//go over the map and check if all the connections are in READY state
		while(iterator.hasNext()){ 
			address = iterator.next();
			plainChannel = (PlainChannel) connections.get(address);
		       if(plainChannel.getState()!=PlainChannel.State.READY){

		    	   iterator.remove();
		    	   //tempConnections.put(address, plainChannel);
		       }
		}
		
		//connections.clear();
		//connections.putAll(tempConnections);
	}
	
	void closeAllConnections(){
		
		Channel channel;
		InetSocketAddress address;
		
		
		//set an iterator for the connection map.
		Iterator<InetSocketAddress> iterator = connections.keySet().iterator();
		
		//go over the map and check if all the connections are in READY state
		while(iterator.hasNext()){ 
			//get the address
			address = iterator.next();
			
			//get the channel
			channel = connections.get(address);
		       
			//close the channel
			channel.close();
		}
	}

}