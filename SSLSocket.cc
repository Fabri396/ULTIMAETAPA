
#include "SSLSocket.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>

#include <sys/socket.h>
#include <unistd.h>

namespace {

std::runtime_error tlsError(const char* operation) {
    unsigned long code = ERR_get_error();
    char message[256] = {};

    if (code != 0) {
        ERR_error_string_n(code, message, sizeof(message));
    } else {
        std::snprintf(message, sizeof(message),
                      "TLS operation failed");
    }

    return std::runtime_error(
        std::string(operation) + ": " + message
    );
}

}

SSLSocket::SSLSocket(bool ipv6) {
    Init('s', ipv6);

    try {
        InitContext(false);
        AttachSSL(false);
    } catch (...) {
        if (BIO) {
            SSL_free(static_cast<SSL*>(BIO));
            BIO = nullptr;
        }

        if (Context) {
            SSL_CTX_free(static_cast<SSL_CTX*>(Context));
            Context = nullptr;
        }

        Close();
        throw;
    }
}

SSLSocket::SSLSocket(
    const char* certificateFile,
    const char* privateKeyFile,
    bool ipv6
) {
    Init('s', ipv6);
    serverMode = true;

    try {
        InitContext(true);
        LoadCertificates(certificateFile, privateKeyFile);
    } catch (...) {
        if (Context) {
            SSL_CTX_free(static_cast<SSL_CTX*>(Context));
            Context = nullptr;
        }

        Close();
        throw;
    }
}

SSLSocket::SSLSocket(
    char* certificateFile,
    char* privateKeyFile,
    bool ipv6
) : SSLSocket(
        static_cast<const char*>(certificateFile),
        static_cast<const char*>(privateKeyFile),
        ipv6
    ) {
}

SSLSocket::SSLSocket(int descriptor) {
    Init(descriptor);

    try {
        InitContext(false);
        AttachSSL(false);
    } catch (...) {
        if (BIO) {
            SSL_free(static_cast<SSL*>(BIO));
            BIO = nullptr;
        }

        if (Context) {
            SSL_CTX_free(static_cast<SSL_CTX*>(Context));
            Context = nullptr;
        }

        Close();
        throw;
    }
}

SSLSocket::SSLSocket(
    int descriptor,
    void* sharedContext
) {
    Init(descriptor);
    serverMode = true;
    Context = sharedContext;

    if (SSL_CTX_up_ref(
        static_cast<SSL_CTX*>(Context)
    ) != 1) {
        Context = nullptr;
        Close();
        throw tlsError("SSL_CTX_up_ref");
    }

    try {
        AttachSSL(true);
    } catch (...) {
        if (BIO) {
            SSL_free(static_cast<SSL*>(BIO));
            BIO = nullptr;
        }

        SSL_CTX_free(static_cast<SSL_CTX*>(Context));
        Context = nullptr;

        Close();
        throw;
    }
}

SSLSocket::~SSLSocket() {
    if (BIO) {
        SSL* ssl = static_cast<SSL*>(BIO);

        if (SSL_is_init_finished(ssl)) {
            SSL_shutdown(ssl);
        }

        SSL_free(ssl);
        BIO = nullptr;
    }

    if (Context) {
        SSL_CTX_free(static_cast<SSL_CTX*>(Context));
        Context = nullptr;
    }
}

void SSLSocket::InitContext(bool server) {
    SSL_CTX* context = SSL_CTX_new(
        server ? TLS_server_method() : TLS_client_method()
    );

    if (!context) {
        throw tlsError("SSL_CTX_new");
    }

    Context = context;

    if (SSL_CTX_set_min_proto_version(
        context, TLS1_2_VERSION
    ) != 1) {
        throw tlsError("SSL_CTX_set_min_proto_version");
    }

    if (server) {
        // Request a certificate if available; ordinary CLI users can connect without one.
        // Registry operations explicitly require a verified warehouse identity.
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_load_verify_locations(context, "certs/siqp-trust.crt", nullptr) != 1)
            throw std::runtime_error("Falta certs/siqp-trust.crt para validar bodegas");
    }
    if (!server) {
        const char* certFile = std::getenv("SIQP_CLIENT_CERT");
        const char* keyFile = std::getenv("SIQP_CLIENT_KEY");
        if ((certFile && *certFile) != (keyFile && *keyFile))
            throw std::runtime_error("SIQP_CLIENT_CERT y SIQP_CLIENT_KEY deben configurarse juntos");
        if (certFile && *certFile) LoadCertificates(certFile, keyFile);
        SSL_CTX_set_verify(
            context,
            SSL_VERIFY_PEER,
            nullptr
        );

        const char* caFile = std::getenv("SIQP_CA_FILE");
        if (caFile && *caFile) {
            if (SSL_CTX_load_verify_locations(context, caFile, nullptr) != 1)
                throw tlsError("SSL_CTX_load_verify_locations");
        } else if (SSL_CTX_load_verify_locations(context, "certs/siqp-trust.crt", nullptr) != 1) {
            throw std::runtime_error("Falta certs/siqp-trust.crt (certificado publico de confianza)");
        }
    }
}

void SSLSocket::LoadCertificates(
    const char* certificateFile,
    const char* privateKeyFile
) {
    if (!certificateFile || !privateKeyFile) {
        throw std::invalid_argument(
            "Certificate and private key are required"
        );
    }

    SSL_CTX* context = static_cast<SSL_CTX*>(Context);

    if (SSL_CTX_use_certificate_chain_file(
        context, certificateFile
    ) != 1) {
        throw tlsError("SSL_CTX_use_certificate_chain_file");
    }

    if (SSL_CTX_use_PrivateKey_file(
        context,
        privateKeyFile,
        SSL_FILETYPE_PEM
    ) != 1) {
        throw tlsError("SSL_CTX_use_PrivateKey_file");
    }

    if (SSL_CTX_check_private_key(context) != 1) {
        throw tlsError("SSL_CTX_check_private_key");
    }
}

void SSLSocket::AttachSSL(bool server) {
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(Context));

    if (!ssl) {
        throw tlsError("SSL_new");
    }

    BIO = ssl;

    if (SSL_set_fd(ssl, sockId) != 1) {
        throw tlsError("SSL_set_fd");
    }

    if (server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }
}

int SSLSocket::FinishConnect(int result) {
    if (result < 0) {
        throw std::runtime_error("TCP connection failed");
    }

    SSL* ssl = static_cast<SSL*>(BIO);

    if (SSL_connect(ssl) != 1) {
        throw tlsError("SSL_connect");
    }

    return 1;
}

int SSLSocket::ConnectVerified(const char* host, int port, const char* identity) {
    if (serverMode || !identity || !*identity) throw std::invalid_argument("Identidad TLS requerida");
    SSL* ssl = static_cast<SSL*>(BIO);
    unsigned char addr[16];
    const bool isIP = inet_pton(AF_INET,identity,addr)==1 || inet_pton(AF_INET6,identity,addr)==1;
    if ((isIP ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),identity) : SSL_set1_host(ssl,identity)) != 1)
        throw tlsError("Identidad TLS");
    if (!isIP && SSL_set_tlsext_host_name(ssl,identity)!=1) throw tlsError("SNI");
    return FinishConnect(TryToConnect(host,std::to_string(port).c_str()));
}

std::string SSLSocket::PeerIdentity() const {
    SSL* ssl=static_cast<SSL*>(BIO);
    if (!ssl || SSL_get_verify_result(ssl)!=X509_V_OK) return "";
    X509* cert=SSL_get1_peer_certificate(ssl);
    if (!cert) return "";
    std::string name;
    GENERAL_NAMES* sans=(GENERAL_NAMES*)X509_get_ext_d2i(cert,NID_subject_alt_name,nullptr,nullptr);
    if (sans) {
        for(int i=0;i<sk_GENERAL_NAME_num(sans);++i) {
            const GENERAL_NAME* entry=sk_GENERAL_NAME_value(sans,i);
            if (entry->type==GEN_DNS) {
                const ASN1_STRING* str=entry->d.dNSName;
                const char* data=(const char*)ASN1_STRING_get0_data(str);
                const int len=ASN1_STRING_length(str);
                if (len>0 && !std::memchr(data,0,len)) {name.assign(data,len);break;}
            }
        }
        GENERAL_NAMES_free(sans);
    }
    X509_free(cert);
    return name;
}

int SSLSocket::Connect(const char* host, int port) {
    if (serverMode) {
        throw std::logic_error(
            "Server socket cannot call Connect"
        );
    }

    SSL* ssl = static_cast<SSL*>(BIO);

    unsigned char addr[16];
    bool isIP = inet_pton(AF_INET,host,addr)==1 || inet_pton(AF_INET6,host,addr)==1;
    if ((isIP ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),host) : SSL_set1_host(ssl,host)) != 1) {
        throw tlsError("SSL_set1_host");
    }

    if (!isIP && SSL_set_tlsext_host_name(ssl, host) != 1) {
        throw tlsError("SSL_set_tlsext_host_name");
    }

    return FinishConnect(TryToConnect(host, port));
}

int SSLSocket::Connect(
    const char* host,
    const char* service
) {
    if (serverMode) {
        throw std::logic_error(
            "Server socket cannot call Connect"
        );
    }

    SSL* ssl = static_cast<SSL*>(BIO);

    unsigned char addr[16];
    bool isIP = inet_pton(AF_INET,host,addr)==1 || inet_pton(AF_INET6,host,addr)==1;
    if ((isIP ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),host) : SSL_set1_host(ssl,host)) != 1) {
        throw tlsError("SSL_set1_host");
    }

    if (!isIP && SSL_set_tlsext_host_name(ssl, host) != 1) {
        throw tlsError("SSL_set_tlsext_host_name");
    }

    return FinishConnect(TryToConnect(host, service));
}

VSocket* SSLSocket::AcceptConnection() {
    if (!serverMode) {
        throw std::logic_error(
            "AcceptConnection requires a TLS server"
        );
    }

    sockaddr_storage address{};
    socklen_t length = sizeof(address);

    int descriptor = accept(
        sockId,
        reinterpret_cast<sockaddr*>(&address),
        &length
    );

    if (descriptor < 0) {
        throw std::runtime_error("TCP accept failed");
    }

    std::unique_ptr<SSLSocket> client;

    try {
        client.reset(new SSLSocket(descriptor, Context));
    } catch (...) {
        // The accepted socket is closed by the constructor
        // if initialization fails.
        throw;
    }

    SSL* ssl = static_cast<SSL*>(client->BIO);

    if (SSL_accept(ssl) != 1) {
        throw tlsError("SSL_accept");
    }

    return client.release();
}

size_t SSLSocket::Read(void* buffer, size_t size) {
    if (!BIO) {
        throw std::logic_error(
            "TLS session is not initialized"
        );
    }

    if (size == 0) {
        return 0;
    }

    SSL* ssl = static_cast<SSL*>(BIO);

    int count = SSL_read(
        ssl,
        buffer,
        static_cast<int>(
            std::min(size, static_cast<size_t>(INT_MAX))
        )
    );

    if (count > 0) {
        return static_cast<size_t>(count);
    }

    int error = SSL_get_error(ssl, count);

    if (error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }

    throw tlsError("SSL_read");
}

size_t SSLSocket::Write(const char* message) {
    return Write(message, std::strlen(message));
}

size_t SSLSocket::Write(
    const void* buffer,
    size_t size
) {
    if (!BIO) {
        throw std::logic_error(
            "TLS session is not initialized"
        );
    }

    size_t sent = 0;

    while (sent < size) {
        int chunk = static_cast<int>(
            std::min(
                size - sent,
                static_cast<size_t>(INT_MAX)
            )
        );

        int result = SSL_write(
            static_cast<SSL*>(BIO),
            static_cast<const char*>(buffer) + sent,
            chunk
        );

        if (result <= 0) {
            throw tlsError("SSL_write");
        }

        sent += static_cast<size_t>(result);
    }

    return sent;
}

void SSLSocket::ShowCerts() {
    if (!BIO) {
        return;
    }

    X509* certificate = SSL_get1_peer_certificate(
        static_cast<SSL*>(BIO)
    );

    if (!certificate) {
        std::puts("No peer certificate");
        return;
    }

    char* subject = X509_NAME_oneline(
        X509_get_subject_name(certificate),
        nullptr,
        0
    );

    char* issuer = X509_NAME_oneline(
        X509_get_issuer_name(certificate),
        nullptr,
        0
    );

    if (subject) {
        std::printf("Subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    if (issuer) {
        std::printf("Issuer: %s\n", issuer);
        OPENSSL_free(issuer);
    }

    X509_free(certificate);
}

const char* SSLSocket::GetCipher() {
    if (!BIO) {
        return nullptr;
    }

    return SSL_get_cipher(static_cast<SSL*>(BIO));
}
