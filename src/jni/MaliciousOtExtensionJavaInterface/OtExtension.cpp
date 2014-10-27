#include "OtExtension.h"

#include "OTExtensionMaliciousReceiver.h"
#include "OTExtensionMaliciousSender.h"

#include <jni.h>

/**
 * Init function 
 * (should be the ctor of a class instead of manipulating globals)
 */
BOOL Init() {
  BYTE seedtmp[SHA1_BYTES];

  // m_aSeed = hash(m_nPID || m_nSeed)
  HASH_CTX sha;
  MPC_HASH_INIT(&sha);
  MPC_HASH_UPDATE(&sha, (BYTE*) &m_nPID, sizeof(m_nPID));
  MPC_HASH_UPDATE(&sha, (BYTE*) m_nSeed, sizeof(m_nSeed));
  MPC_HASH_FINAL(&sha, m_aSeed);

  // m_aOTSeed = hash(m_nPID || m_aSeed)
  MPC_HASH_INIT(&sha);
  MPC_HASH_UPDATE(&sha, (BYTE*) &m_nPID, sizeof(m_nPID));
  MPC_HASH_UPDATE(&sha, (BYTE*) m_aSeed, SHA1_BYTES);
  MPC_HASH_FINAL(&sha, seedtmp);
  memcpy(m_aOTSeed, seedtmp, AES_BYTES);

  m_nCounter = 0;

  // TODO: init the class var num of threads
  // Number of threads that will be used in OT extension
  // m_nNumOTThreads = numOfThreads;

  //Number of threads that will be used in OT extension
  m_vSockets.resize(m_nNumOTThreads+1);
  bot = new PVWDDH(m_sSecLvl, m_aSeed);
  
  return TRUE;
}


/**
 * closes all the open sockets
 * (should be a member of a class instead of manipulating globals)
 */
BOOL Cleanup() {
  for(int i = 0; i < m_nNumOTThreads; i++) {
      m_vSockets[i].Close();
  }
  return true;
}

/**
 * initiates a connection (via socket) for each thread on the client
 * (should be a member of a class instead of manipulating globals)
 */
BOOL Connect() {
  BOOL bFail = FALSE;
  LONG lTO = CONNECT_TIMEO_MILISEC;
  int nconnections = m_nNumOTThreads+1;

#ifndef BATCH
  cout << "Connecting to party "<< !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif

  // try to initiate connection for socket k
  for(int k = nconnections-1; k >= 0 ; k--) {
    // iterate on retries
    for(int i=0; i<RETRY_CONNECT; i++) {
      if(!m_vSockets[k].Socket()) {
	printf("Socket failure: ");
	goto connect_failure;
      }
			
      if(m_vSockets[k].Connect(m_nAddr, m_nPort, lTO)) {
	// connected to other side!

	// send the thread id when connected
	m_vSockets[k].Send(&k, sizeof(int));

#ifndef BATCH
	cout << " (" << !m_nPID << ") (" << k << ") connected" << endl;
#endif

	if(k == 0) {
	  //cout << "connected" << endl;
	  return TRUE;
	} else {
	  // socket k is connected, breaking the "retries" loop
	  // and moving on to the next socket.
	  break;
	}

	// TODO: weird: seems to me that this code will never execute!
	// SleepMiliSec(10);
	// m_vSockets[k].Close();
      }

      // unable to connect!
      
      // if all allowed retries failed, server is unavailable
      if(i+1 == RETRY_CONNECT) {
	goto server_not_available;
      }

      // else, waiting 20 milliseconds before retry
      SleepMiliSec(20);
    }
  }
 server_not_available:
  printf("Server not available: ");
 connect_failure:
  cout << " (" << !m_nPID << ") connection failed" << endl;
  return FALSE;
}

/**
 * listens and accepts connections on the server
 * (should be a member of a class instead of manipulating globals)
 */
BOOL Listen()
{
#ifndef BATCH
  cout << "Listening: " << m_nAddr << ":" << m_nPort << ", with size: " << m_nNumOTThreads << endl;
#endif
  int nconnections = m_nNumOTThreads+1;

  // verify the socket object
  if(!m_vSockets[0].Socket()) {
      goto listen_failure;
  }
  
  // try to bind()
  if(!m_vSockets[0].Bind(m_nPort, m_nAddr)) {
    goto listen_failure;
  }

  // try to listen()
  if(!m_vSockets[0].Listen()) {
    goto listen_failure;
  }

  for(int i = 0; i<nconnections; i++) { //twice the actual number, due to double sockets for OT
    CSocket sock;
    //cout << "New round! " << endl;

    // try: CSocket sock = accept()
    if(!m_vSockets[0].Accept(sock)) {
      cerr << "Error in accept" << endl;
      goto listen_failure;
    }
    
    // receive the other side thread id (the first thing that is sent on the socket)
    UINT threadID;
    sock.Receive(&threadID, sizeof(int));
    
    if(threadID >= nconnections) {
      sock.Close();
      i--;
      continue;
    }

#ifndef BATCH
    cout <<  " (" << m_nPID <<") (" << threadID << ") connection accepted" << endl;
#endif
    // locate the socket appropriately
    m_vSockets[threadID].AttachFrom(sock);
    sock.Detach();
  }

#ifndef BATCH
  cout << "Listening finished"  << endl;
#endif
  return TRUE;

 listen_failure:
  cout << "Listen failed" << endl;
  return FALSE;
}

/**
 * init the ot sender (and performs the base ot as the receiver)
 * (should be a member of a class instead of manipulating globals)
 */
Mal_OTExtensionSender * InitOTSender(const char* address, int port, int nbaseots, int numOTs)
{
  int nSndVals = 2;
  int wdsize = 1 << (CEIL_LOG2(nbaseots));
  int nblocks = CEIL_DIVIDE(numOTs, NUMOTBLOCKS * wdsize);
  int s2ots = nblocks * nbaseots;

#ifdef OTTiming
  timeval np_begin, np_end, s2_begin, s2_end;
#endif

  m_nPort = (USHORT) port;
  m_nAddr = address;
  //key seed matrix used for the 1-step base OTs
  vKeySeedMtx = (BYTE*) malloc(AES_KEY_BYTES * nbaseots * nSndVals);
  //key seeds for the 2-nd step base OTs
  vKeySeeds = (BYTE*) malloc(AES_KEY_BYTES * s2ots);//m_sSecLvl.symbits);

  //Initialize values
  Init();
	
  //Server listen
  Listen();
	
#ifdef OTTiming
  gettimeofday(&np_begin, NULL);
#endif

  // precompute base ot
  PrecomputeBaseOTsSender(nbaseots);

#ifdef OTTiming
  gettimeofday(&np_end, NULL);
#ifdef BATCH
  cout << getMillies(np_begin, np_end) << "\t";
#else
  printf("Time for performing the NP base-OTs: %f ms\n", getMillies(np_begin, np_end));
#endif
  gettimeofday(&s2_begin, NULL);
#endif	

  CBitVector seedcbitvec;
  CBitVector U(s2ots, m_aSeed, m_nCounter);
  CBitVector URev(s2ots);

  seedcbitvec.AttachBuf(vKeySeeds, AES_KEY_BYTES * s2ots);

  XORMasking* mskfct = new XORMasking(AES_KEY_BITS);

  assert(nblocks <= NUMOTBLOCKS);

  //cout << "Initializing OT extension receiver " << endl;
  //perform the 2nd OT extension step to obtain the base-OTs for the next step
  receiver = new Mal_OTExtensionReceiver(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), vKeySeedMtx, m_aSeed, nbaseots, s2ots);

  receiver->receive(s2ots, AES_KEY_BITS, U, seedcbitvec, R_OT, 1, mskfct);

  for(int i = 0; i < s2ots; i++) {
    //cout << i << ": " << (hex) << ((uint64_t*) (vKeySeeds +  i * AES_KEY_BYTES))[0] << ((uint64_t*)(vKeySeeds + i * AES_KEY_BYTES))[1] << (dec) << endl;
    URev.SetBit(i, U.GetBitNoMask(i));
  }
  //URev.PrintBinary();
  sender = new Mal_OTExtensionSender (nSndVals, m_sSecLvl.symbits, m_vSockets.data(), URev, vKeySeeds, nbaseots, m_nChecks, s2ots, m_aOTSeed);

#ifdef OTTiming
  gettimeofday(&s2_end, NULL);
#ifdef BATCH
  cout << getMillies(s2_begin, s2_end) << "\t";
#else
  printf("Time for performing the 2nd-step base-OTs: %f ms\n", getMillies(s2_begin, s2_end));
#endif
#endif

  return sender;
}

/**
 * inits the ot receiver (and performs the base ot as the sender)
 * (should be a member of a class instead of manipulating globals)
 */
void InitOTReceiver(const char* address, int port, int nbaseots, int numOTs)
{
  int nSndVals = 2;
  int wdsize = 1 << (CEIL_LOG2(nbaseots));
  int nblocks = CEIL_DIVIDE(numOTs, NUMOTBLOCKS * wdsize);
  int s2ots = nblocks * nbaseots;
  //cout << "nblocks = " << nblocks <<", baseots = " << nbaseots << ", s2ots: " << s2ots << endl;

#ifdef OTTiming
  timeval np_begin, np_end, s2_begin, s2_end;
#endif

  m_nPort = (USHORT) port;
  m_nAddr = address;
  vKeySeeds = (BYTE*) malloc(AES_KEY_BYTES*nbaseots);//m_sSecLvl.symbits);
  vKeySeedMtx = (BYTE*) malloc(AES_KEY_BYTES * 2 * s2ots);

  //Initialize values
  Init();
	
  //Client connect
  Connect();
	
#ifdef OTTiming
  gettimeofday(&np_begin, NULL);
#endif

  //First step: pre-compute the PVW base OTs
  PrecomputeBaseOTsReceiver(nbaseots);

#ifdef OTTiming
  gettimeofday(&np_end, NULL);
#ifdef BATCH
  cout << getMillies(np_begin, np_end) << "\t";
#else
  printf("Time for performing the NP base-OTs: %f ms\n", getMillies(np_begin, np_end));
#endif
  gettimeofday(&s2_begin, NULL);
#endif	

  assert(nblocks <= NUMOTBLOCKS);

  //perform the 2nd OT extension step to obtain the base-OTs for the next step
  sender = new Mal_OTExtensionSender (nSndVals, m_sSecLvl.symbits, m_vSockets.data(), U, vKeySeeds, nbaseots, m_nChecks, s2ots, m_aOTSeed);
  CBitVector seedA(s2ots * AES_KEY_BITS);
  CBitVector seedB(s2ots * AES_KEY_BITS);

  XORMasking* mskfct = new XORMasking(AES_KEY_BITS);
  sender->send(s2ots, AES_KEY_BITS, seedA, seedB, R_OT, 1, mskfct);

  for(int i = 0; i < s2ots; i++) {
    memcpy(vKeySeedMtx + 2 * i * AES_KEY_BYTES, seedA.GetArr() + i * AES_KEY_BYTES, AES_KEY_BYTES);
    memcpy(vKeySeedMtx + (2*i+1) * AES_KEY_BYTES, seedB.GetArr() + i * AES_KEY_BYTES, AES_KEY_BYTES);
  }
  receiver = new Mal_OTExtensionReceiver(nSndVals, m_sSecLvl.symbits, m_vSockets.data(), vKeySeedMtx, m_aSeed, nbaseots, s2ots);

#ifdef OTTiming
  gettimeofday(&s2_end, NULL);
#ifdef BATCH
  cout << getMillies(s2_begin, s2_end) << "\t";
#else
  printf("Time for performing the 2nd-step base-OTs: %f ms\n", getMillies(s2_begin, s2_end));
#endif
#endif
}

/**
 * PrecomputeBaseOTsReceiver
 * (should be a member of a class instead of manipulating globals)
 */
BOOL PrecomputeBaseOTsReceiver(int numbaseOTs)
{

  int nSndVals = 2;
  BYTE* pBuf = new BYTE[numbaseOTs * SHA1_BYTES];
  int log_nVals = (int) ceil(log(nSndVals)/log(2));
  int cnt = 0;
	
  U.Create(numbaseOTs * log_nVals, m_aSeed, cnt);
	
  bot->Receiver(nSndVals, numbaseOTs, U, m_vSockets[0], pBuf);
	
  //Key expansion
  BYTE* pBufIdx = pBuf;
  for(int i=0; i<numbaseOTs; i++ ) //80 HF calls for the Naor Pinkas protocol
    {
      memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
      pBufIdx+=SHA1_BYTES;
    } 
  delete [] pBuf;	

  return true;
}

/**
 * PrecomputeBaseOTsSender
 * (should be a member of a class instead of manipulating globals)
 */
BOOL PrecomputeBaseOTsSender(int numbaseOTs)
{
  int nSndVals = 2;
  // Execute NP receiver routine and obtain the key 
  BYTE* pBuf = new BYTE[SHA1_BYTES * numbaseOTs * nSndVals];

  //=================================================	
  bot->Sender(nSndVals, numbaseOTs, m_vSockets[0], pBuf);
	
  BYTE* pBufIdx = pBuf;
  for(int i=0; i<numbaseOTs * nSndVals; i++ )
    {
      memcpy(vKeySeedMtx + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
      pBufIdx += SHA1_BYTES;
    }
	
  delete [] pBuf;	

  return true;
}

/**
 * ObliviouslySend
 * (should be a member of a class instead of manipulating globals)
 */
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, 
		     BYTE version, CBitVector& delta)
{
  bool success = FALSE;
  int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
  timeval ot_begin, ot_end;
#endif

	
#ifdef OTTiming
  gettimeofday(&ot_begin, NULL);
#endif
  // Execute OT sender routine 	
  success = sender->send(numOTs, bitlength, X1, X2, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
  gettimeofday(&ot_end, NULL);
#ifdef BATCH
  cout << getMillies(ot_begin, ot_end) + rndgentime << "\t";
#else
  printf("Sender: time for OT extension %f ms\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
#endif
  return success;
}

/**
 * ObliviouslyReceive
 * (should be a member of a class instead of manipulating globals)
 */
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version)
{
  bool success = FALSE;

#ifdef OTTiming
  timeval ot_begin, ot_end;
  gettimeofday(&ot_begin, NULL);
#endif
  // Execute OT receiver routine 	
  success = receiver->receive(numOTs, bitlength, choices, ret, version, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
  gettimeofday(&ot_end, NULL);
#ifdef BATCH
  cout << getMillies(ot_begin, ot_end) + rndgentime << "\t";
#else
  printf("Receiver: time for OT extension %f ms\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
#endif

	
  return success;
}
