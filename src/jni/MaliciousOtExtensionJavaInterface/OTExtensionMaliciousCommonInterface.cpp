#include "OTExtensionMaliciousCommonInterface.h"

namespace maliciousot {


/**
 * inits the seeds required by the ot protocol
 */
void OTExtensionMaliciousCommonInterface::init_seeds(int role) {
  BYTE seedtmp[SHA1_BYTES];
  HASH_CTX sha;

  // m_receiver_seed = hash(role || m_initial_seed)
  MPC_HASH_INIT(&sha);
  MPC_HASH_UPDATE(&sha, (BYTE*) &role, sizeof(role));
  MPC_HASH_UPDATE(&sha, (BYTE*) m_initial_seed, sizeof(m_initial_seed));
  MPC_HASH_FINAL(&sha, m_receiver_seed);

  // m_sender_seed = hash(role || m_receiver_seed)
  MPC_HASH_INIT(&sha);
  MPC_HASH_UPDATE(&sha, (BYTE*) &role, sizeof(role));
  MPC_HASH_UPDATE(&sha, (BYTE*) m_receiver_seed, SHA1_BYTES);
  MPC_HASH_FINAL(&sha, seedtmp);
  memcpy(m_sender_seed, seedtmp, AES_BYTES);
}

OTExtensionMaliciousCommonInterface::OTExtensionMaliciousCommonInterface(int role,
									 int num_base_ots, 
									 int num_ots) {
    m_num_base_ots = num_base_ots;
    m_num_ots = num_ots;
    m_counter = 0;

    init_seeds(role);
    
    m_baseot_handler = new PVWDDH(m_security_level, m_receiver_seed);
}

void OtExtensionMaliciousReceiverInterface::InitOTReceiver() {

}

BOOL OtExtensionMaliciousReceiverInterface::PrecomputeBaseOTsReceiver(int nbaseots);
BOOL OtExtensionMaliciousReceiverInterface::ObliviouslyReceive(CBitVector& choices, 
							       CBitVector& ret, 
							       int numOTs, 
							       int bitlength, 
							       BYTE version);

}
