#ifndef _OTEXT_MALICIOUS_JNI_H_
#define _OTEXT_MALICIOUS_JNI_H_

#ifdef _WIN32

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/cbitvector.h"
#include "../ot/ot-extension-malicious.h"
#include "../ot/xormasking.h"
#include "../ot/pvwddh.h"
#else
#include <MaliciousOTExtension/util/typedefs.h>
#include <MaliciousOTExtension/util/socket.h>
#include <MaliciousOTExtension/util/cbitvector.h>
#include <MaliciousOTExtension/ot/ot-extension-malicious.h>
#include <MaliciousOTExtension/ot/xormasking.h>
#include <MaliciousOTExtension/ot/pvwddh.h>
#endif

#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;

static const char* m_nSeed = "437398417012387813714564100";

USHORT		m_nPort = 7766;
const char* m_nAddr ;// = "localhost";

BOOL Init();
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(const char* address, int port, int nbaseots, int numOTs);
void InitOTReceiver(const char* address, int port, int nbaseots, int numOTs);

BOOL PrecomputeBaseOTsSender(int nbaseots);
BOOL PrecomputeBaseOTsReceiver(int nbaseots);
BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version);

/* OTExtensionSender* InitOTSender(const char* address, int port); */
/* OTExtensionReceiver* InitOTReceiver(const char* address, int port); */

/* BOOL PrecomputeNaorPinkasSender(); */
/* BOOL PrecomputeNaorPinkasReceiver(); */
/* BOOL ObliviouslyReceive(OTExtensionReceiver* receiver, CBitVector& choices, CBitVector& ret, int numOTs, int bitlength, BYTE version); */
/* BOOL ObliviouslySend(OTExtensionSender* sender, CBitVector& X1, CBitVector& X2, int numOTs, int bitlength, BYTE version, CBitVector& delta); */

// Network Communication
vector<CSocket> m_vSockets;
int m_nPID; // thread id
SECLVL m_sSecLvl; /* instead of int m_nSecParam; in semi-honest*/
bool m_bUseECC;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;


// Naor-Pinkas OT
BaseOT* bot;

CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

// ot extension sender and receiver pointers (should be ret values!)
Mal_OTExtensionSender *sender;
Mal_OTExtensionReceiver *receiver;

// Naor-Pinkas OT
BaseOT* bot;

CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

// threads
int m_nNumOTThreads;

// SHA PRG
BYTE m_aSeed[SHA1_BYTES];
BYTE m_aOTSeed[AES_BYTES]; /* new in malicious */
double rndgentime;
int m_nCounter;
int m_nChecks; /* new in malicious */


#endif //_MPC_H_
