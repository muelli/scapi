#ifndef _OTEXT_CONNECTION_MANAGER_H_
#define _OTEXT_CONNECTION_MANAGER_H_

#include <MaliciousOTExtension/util/typedefs.h>
#include <MaliciousOTExtension/util/socket.h>

#include <limits.h>
#include <iomanip>
#include <vector>
#include <sys/time.h>

namespace maliciousot {

// abstract base class
class ConnectionManager {

 public:
    static const char * DEFAULT_ADDRESS = "localhost";
    static const USHORT DEFAULT_PORT = 7766;

    // ctors
    ConnectionManager(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManager(int role);
    
    void cleanup();
    inline CSocket * get_sockets_data() { return m_sockets.data(); };
    inline const CSocket& get_socket(int i) { return m_sockets[i]; };
    inline int get_num_of_threads() { return m_num_of_threads; };
    virtual BOOL setup_connection() = 0;
    
 protected:
    int m_num_of_threads;
    const char* m_address;
    USHORT m_port;
    int m_pid; // thread id - indicates the role: (0 for server, 1 for client)
    std::vector<CSocket> m_sockets;
};

// server class (used by sender)
class ConnectionManagerServer : public ConnectionManager {
    ConnectionManagerServer(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManagerServer(int role);
    virtual BOOL setup_connection();
};

// client class (used by receiver)
class ConnectionManagerClient : public ConnectionManager {
    ConnectionManagerClient(int role, int num_of_threads, const char * address, int port);
    explicit ConnectionManagerClient(int role);
    virtual BOOL setup_connection();
};

#endif //_OTEXT_CONNECTION_MANAGER_H_
