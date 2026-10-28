
#ifndef SSLSocket_h
#define SSLSocket_h

#include <cstddef>
#include <string>
#include "VSocket.h"

class SSLSocket : public VSocket {
public:
    explicit SSLSocket(bool IPv6 = false);

    SSLSocket(const char* certificateFile,
              const char* privateKeyFile,
              bool IPv6 = false);

    SSLSocket(char* certificateFile,
              char* privateKeyFile,
              bool IPv6 = false);

    explicit SSLSocket(int descriptor);

    ~SSLSocket();

    int Connect(const char* host, int port) override;
    int ConnectVerified(const char* host, int port, const char* identity);
    std::string PeerIdentity() const;
    int Connect(const char* host, const char* service) override;

    size_t Read(void* buffer, size_t size) override;
    size_t Write(const void* buffer, size_t size) override;
    size_t Write(const char* message) override;

    VSocket* AcceptConnection() override;

    void ShowCerts();
    const char* GetCipher();

private:
    void* Context = nullptr;
    void* BIO = nullptr;

    bool serverMode = false;

    void InitContext(bool server);
    void LoadCertificates(const char* certificateFile,
                          const char* privateKeyFile);
    void AttachSSL(bool server);
    int FinishConnect(int result);

    SSLSocket(int descriptor, void* sharedContext);

    SSLSocket(const SSLSocket&) = delete;
    SSLSocket& operator=(const SSLSocket&) = delete;
};

#endif
