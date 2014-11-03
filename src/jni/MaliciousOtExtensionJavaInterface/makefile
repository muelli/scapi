# this makefile should be activated using the main scapi makefile:
# > cd [SCAPI_ROOT]
# > make jni-otextension

# compilation options
CXX=g++-4.9
CXXFLAGS=-std=c++0x -g -fPIC
prefix=/usr
includedir=/Users/asafc/projects/university
libdir=/Users/asafc/projects/university/MaliciousOTExtension
JAVA_HOME=$(shell /usr/libexec/java_home)

SHARED_LIB_OPT=-dynamiclib
SHARED_LIB_EXT=.dylib
JNI_LIB_EXT=.jnilib

# dependencies

INCLUDES=-I$(prefix)/include -I$(includedir) -I$(prefix)/ssl/include -I$(JAVA_HOME)/include/ -I$(JAVA_HOME)/include/darwin/
LIBRARIES_DIR=-L$(prefix)/ssl/lib -L$(libdir) -L$(prefix)/lib
LIBRARIES=$(INCLUDE_ARCHIVES_START) /usr/lib/libmiracl.a -lssl -lcrypto -lMaliciousOTExtension $(INCLUDE_ARCHIVES_END)

# objects
OT_JNI_OBJECTS = ConnectionManager.o OTExtensionMaliciousCommonInterface.o OTExtensionMaliciousReceiverInterface.o OTExtensionMaliciousSenderInterface.o OTExtensionMaliciousReceiver.o OTExtensionMaliciousSender.o

## targets ##

# main target - linking individual *.o files
libMaliciousOtExtensionJavaInterface$(JNI_LIB_EXT): $(OT_JNI_OBJECTS)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OT_JNI_OBJECTS) $(INCLUDES) $(LIBRARIES_DIR) $(LIBRARIES)

ConnectionManager.o: ConnectionManager.cpp
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousCommonInterface.o: OTExtensionMaliciousCommonInterface.cpp ConnectionManager.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousReceiverInterface.o: OTExtensionMaliciousReceiverInterface.cpp OTExtensionMaliciousCommonInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousSenderInterface.o: OTExtensionMaliciousSenderInterface.cpp OTExtensionMaliciousCommonInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousReceiver.o: OTExtensionMaliciousReceiver.cpp OTExtensionMaliciousReceiverInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

OTExtensionMaliciousSender.o: OTExtensionMaliciousSender.cpp OTExtensionMaliciousSenderInterface.o
	$(CXX) $(CXXFLAGS) -c $< $(INCLUDES)

clean:
	rm -f *~
	rm -f *.o
	rm -f *.jnilib
