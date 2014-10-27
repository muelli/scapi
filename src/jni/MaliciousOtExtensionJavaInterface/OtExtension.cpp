#include "OtExtension.h"

/**
 * init the ot sender (and performs the base ot as the receiver)
 * (should be a member of a class instead of manipulating globals)
 */
Mal_OTExtensionSender * InitOTSender(const char* address, int port, int m_num_base_ots, int m_num_ots)
{
  int nSndVals = 2;
  int wdsize = 1 << (CEIL_LOG2(m_num_base_ots));
  int nblocks = CEIL_DIVIDE(m_num_ots, NUMOTBLOCKS * wdsize);
  int s2ots = nblocks * m_num_base_ots;

#ifdef OTTiming
  timeval np_begin, np_end, s2_begin, s2_end;
#endif

  m_port = (USHORT) port;
  m_address = address;
  //key seed matrix used for the 1-step base OTs
  m_receiver_key_seeds_matrix = (BYTE*) malloc(AES_KEY_BYTES * m_num_base_ots * nSndVals);
  //key seeds for the 2-nd step base OTs
  m_sender_key_seeds = (BYTE*) malloc(AES_KEY_BYTES * s2ots);//m_security_level.symbits);

  //Initialize values
  Init();
	
  //Server listen
  Listen();
	
#ifdef OTTiming
  gettimeofday(&np_begin, NULL);
#endif

  // precompute base ot
  PrecomputeBaseOTsSender(m_num_base_ots);

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
  CBitVector U(s2ots, m_receiver_seed, m_counter);
  CBitVector URev(s2ots);

  seedcbitvec.AttachBuf(m_sender_key_seeds, AES_KEY_BYTES * s2ots);

  XORMasking* mskfct = new XORMasking(AES_KEY_BITS);

  assert(nblocks <= NUMOTBLOCKS);

  //cout << "Initializing OT extension receiver " << endl;
  //perform the 2nd OT extension step to obtain the base-OTs for the next step
  m_receiver = new Mal_OTExtensionReceiver(nSndVals, m_security_level.symbits, m_sockets.data(), 
					 m_receiver_key_seeds_matrix, m_receiver_seed, m_num_base_ots, s2ots);

  m_receiver->receive(s2ots, AES_KEY_BITS, U, seedcbitvec, R_OT, 1, mskfct);

  for(int i = 0; i < s2ots; i++) {
    //cout << i << ": " << (hex) << ((uint64_t*) (m_sender_key_seeds +  i * AES_KEY_BYTES))[0] << ((uint64_t*)(m_sender_key_seeds + i * AES_KEY_BYTES))[1] << (dec) << endl;
    URev.SetBit(i, U.GetBitNoMask(i));
  }
  //URev.PrintBinary();
  m_sender = new Mal_OTExtensionSender(nSndVals, m_security_level.symbits, m_sockets.data(), 
				     URev, m_sender_key_seeds, m_num_base_ots, m_num_checks, s2ots, m_sender_seed);

#ifdef OTTiming
  gettimeofday(&s2_end, NULL);
#ifdef BATCH
  cout << getMillies(s2_begin, s2_end) << "\t";
#else
  printf("Time for performing the 2nd-step base-OTs: %f ms\n", getMillies(s2_begin, s2_end));
#endif
#endif

  return m_sender;
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
  m_baseot_handler->Sender(nSndVals, numbaseOTs, m_sockets[0], pBuf);
	
  BYTE* pBufIdx = pBuf;
  for(int i=0; i<numbaseOTs * nSndVals; i++ )
    {
      memcpy(m_receiver_key_seeds_matrix + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
      pBufIdx += SHA1_BYTES;
    }
	
  delete [] pBuf;	

  return true;
}

/**
 * ObliviouslySend
 * (should be a member of a class instead of manipulating globals)
 */
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int m_num_ots, int bitlength, 
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
  success = m_sender->send(m_num_ots, bitlength, X1, X2, version, m_num_of_threads, m_masking_function);
	
#ifdef OTTiming
  gettimeofday(&ot_end, NULL);
#ifdef BATCH
  cout << getMillies(ot_begin, ot_end) + logger_random_gentime << "\t";
#else
  printf("Sender: time for OT extension %f ms\n", getMillies(ot_begin, ot_end) + logger_random_gentime);
#endif
#endif
  return success;
}
