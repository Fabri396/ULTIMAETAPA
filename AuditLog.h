#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <sys/stat.h>

namespace AuditLog {
inline std::mutex& mutex() { static std::mutex m; return m; }
inline std::string clean(const std::string& input) {
    std::string output;
    for (size_t i = 0; i < input.size(); ++i) {
        if (input.compare(i, 6, "token=") == 0) {
            output += "token=[REDACTED]";
            i += 6;
            while (i < input.size() && input[i] != ';' && input[i] != '|') ++i;
            if (i < input.size()) output += input[i];
            else break;
        } else if (input[i] == '\n' || input[i] == '\r') output += ' ';
        else output += input[i];
    }
    return output;
}
inline void write(const std::string& server, const std::string& event,
                  const std::string& detail) {
    std::lock_guard<std::mutex> lock(mutex());
    if (mkdir("logs", 0755) != 0) { /* Existing directory is normal. */ }
    std::ofstream file(("logs/" + server + ".log").c_str(), std::ios::app);
    if (!file) { std::cerr << "No se pudo escribir bitacora de " << server << '\n'; return; }
    std::time_t now = std::time(nullptr);
    std::tm local = {};
    localtime_r(&now, &local);
    file << std::put_time(&local, "%Y-%m-%d %H:%M:%S")
         << " | " << event << " | " << clean(detail) << '\n';
}
}
#endif
