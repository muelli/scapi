package edu.biu.scapi.anonymousForums;

import java.io.Serializable;

import edu.biu.scapi.primitives.dlog.GroupElement;

class GroupElementPair implements Serializable{
	/**
	 * 
	 */
	//private final ForumUser forumUser;
	/**
	 * 
	 */
	private static final long serialVersionUID = -9017195578964212420L;
	GroupElement first;
	GroupElement second;

	public GroupElementPair(/*ForumUser forumUser, */GroupElement first, GroupElement second) {
//		this.forumUser = forumUser;
		this.first = first;
		this.second = second;
	}

	public GroupElement getFirst() {
		return first;
	}

	public GroupElement getSecond() {
		return second;
	}

	public void release() {
		first.release();
		second.release();
	}
/*
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + getOuterType().hashCode();
		result = prime * result + ((first == null) ? 0 : first.hashCode());
		result = prime * result
				+ ((second == null) ? 0 : second.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GroupElementPair other = (GroupElementPair) obj;
		if (!getOuterType().equals(other.getOuterType()))
			return false;
		if (first == null) {
			if (other.first != null)
				return false;
		} else if (!first.equals(other.first))
			return false;
		if (second == null) {
			if (other.second != null)
				return false;
		} else if (!second.equals(other.second))
			return false;
		if(this.first.equals(other.first) && this.second.equals(other.second))
			return true;
		return false;
	}

	private ForumUser getOuterType() {
		return this.forumUser;
	}
	*/
	
}