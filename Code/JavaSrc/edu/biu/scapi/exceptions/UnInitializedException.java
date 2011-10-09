package edu.biu.scapi.exceptions;

public class UnInitializedException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public String getMessage(){
		return "cannot perform any function before initialization";
	}
}
