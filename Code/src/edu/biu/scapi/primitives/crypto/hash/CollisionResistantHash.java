/**
 * A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, 
 * the (cryptographic) hash value. There are two main levels of security that we will consider here: target collision resistance for which we have a (meaning that given x it is hard to find y such that H(y)=H(x)) and 
 * collision resistance (meaning that it is hard to find any x and y such that H(x)=H(y)). 
 * 
 */
package edu.biu.scapi.primitives.crypto.hash;

/** 
 * @author LabTest
 */
public interface CollisionResistantHash extends TargetCollisionResistant {
}