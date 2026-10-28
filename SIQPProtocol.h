
#ifndef SIQP_PROTOCOL_H
#define SIQP_PROTOCOL_H

#include <string>
#include <map>

#include "FileSystem.h"

struct SIQPMessage {
    std::string version;
    int type = 0;
    std::string messageId;
    std::string source;
    std::string destination;
    std::string body;
};

class SIQPProtocol {
public:
    static SIQPMessage parseMessage(
        const std::string& rawMessage
    );

    static std::string buildMessage(
        const SIQPMessage& message
    );

    static std::string processRequest(
        const std::string& rawMessage,
        FileSystem& filesystem,
        const std::string& serverId = "SI-01"
    );

    static std::string escapeValue(
        const std::string& value
    );

    static std::string unescapeValue(
        const std::string& value
    );

private:
    static std::map<std::string, std::string> parseBody(
        const std::string& body
    );

    static std::string normalize(
        const std::string& value
    );

    static std::string join(
        const std::vector<std::string>& values
    );
};

#endif
