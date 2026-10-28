
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "FileSystem.h"
#include "SIQPProtocol.h"

#define COMMON_PORT 9090
#define BUFFER_SIZE 8192

std::vector<std::string> split(
    const std::string &text,
    char delimiter
) {
    std::vector<std::string> result;
    std::string current;

    for (char character : text) {
        if (character == delimiter) {
            result.push_back(current);
            current.clear();
        } else {
            current += character;
        }
    }

    result.push_back(current);
    return result;
}

std::string getAttribute(
    const std::string &body,
    const std::string &key
) {
    for (const std::string &entry : split(body, ';')) {
        size_t position = entry.find('=');

        if (position != std::string::npos &&
            entry.substr(0, position) == key) {
            return entry.substr(position + 1);
        }
    }

    return "";
}

std::string lower(const std::string &value) {
    std::string result = value;

    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char character) {
            return static_cast<char>(
                std::tolower(character)
            );
        }
    );

    return result;
}

bool validName(const std::string &name) {
    if (name.empty() || name.size() > 50) {
        return false;
    }

    for (unsigned char character : name) {
        if (!std::isalnum(character) &&
            character != '_' &&
            character != '-') {
            return false;
        }
    }

    return true;
}

std::string buildSiqpRequest(
    const std::string &type,
    const std::string &body,
    unsigned int messageNumber
) {
    std::ostringstream messageId;

    messageId << std::setw(5)
              << std::setfill('0')
              << messageNumber;

    return "SIQP/1.0|" + type + "|" +
           messageId.str() +
           "|INT-02|SI-02|" + body;
}

std::string executeSiqp(
    FileSystem &filesystem,
    const std::string &type,
    const std::string &body,
    unsigned int &messageNumber
) {
    std::string request = buildSiqpRequest(
        type,
        body,
        messageNumber++
    );

    std::cout
        << "[MANCOMUNADO -> SIQP] "
        << request << std::endl;

    std::string response =
        SIQPProtocol::processRequest(
            request,
            filesystem,
            "SI-02"
        );

    std::cout
        << "[SIQP -> MANCOMUNADO] "
        << response << std::endl;

    return response;
}

std::string processRequest(
    FileSystem &filesystem,
    const std::string &message,
    unsigned int &messageNumber
) {
    std::vector<std::string> fields =
        split(message, '/');

    if (fields.empty()) {
        return "02/100";
    }

    if (fields[0] == "10") {
        if (fields.size() != 1) {
            return "02/100";
        }

        std::string response = executeSiqp(
            filesystem,
            "12",
            "",
            messageNumber
        );

        std::vector<std::string> siqp =
            split(response, '|');

        if (siqp.size() != 6 || siqp[1] != "13") {
            return "02/100";
        }

        std::string categories =
            getAttribute(siqp[5], "categorias");

        return "01/" + categories;
    }

    if (fields[0] == "20") {
        if (fields.size() != 2) {
            return "02/100";
        }

        std::string category = lower(fields[1]);

        if (!validName(category)) {
            return "02/102";
        }

        std::string categoryResponse = executeSiqp(
            filesystem,
            "12",
            "",
            messageNumber
        );

        std::vector<std::string> categoryFields =
            split(categoryResponse, '|');

        if (categoryFields.size() != 6 ||
            categoryFields[1] != "13") {
            return "02/100";
        }

        bool exists = false;

        std::string categories =
            getAttribute(
                categoryFields[5],
                "categorias"
            );

        for (const std::string &current :
             split(categories, ',')) {
            if (lower(current) == category) {
                exists = true;
                break;
            }
        }

        if (!exists) {
            return "03/" + category;
        }

        std::string productResponse = executeSiqp(
            filesystem,
            "14",
            "categoria=" + category,
            messageNumber
        );

        std::vector<std::string> productFields =
            split(productResponse, '|');

        if (productFields.size() != 6 ||
            productFields[1] != "15") {
            return "02/100";
        }

        std::string names =
            getAttribute(
                productFields[5],
                "productos"
            );

        if (names.empty()) {
            return "01/0/";
        }

        std::vector<std::string> products =
            split(names, ',');

        std::string result;
        size_t count = 0;

        for (const std::string &product : products) {
            if (!validName(product)) {
                return "02/100";
            }

            std::string infoResponse = executeSiqp(
                filesystem,
                "18",
                "categoria=" + category +
                ";producto=" + product,
                messageNumber
            );

            std::vector<std::string> infoFields =
                split(infoResponse, '|');

            if (infoFields.size() != 6 ||
                infoFields[1] != "19") {
                return "02/100";
            }

            std::string price =
                getAttribute(infoFields[5], "precio");

            std::string stock =
                getAttribute(infoFields[5], "cantidad");

            if (price.empty() || stock.empty()) {
                return "02/100";
            }

            if (!result.empty()) {
                result += ";";
            }

            result += product + "," +
                      price + "," + stock;

            ++count;
        }

        return "01/" +
               std::to_string(count) +
               "/" + result;
    }

    return "02/101";
}

int main(int argc, char **argv) {
    const std::string inventoryFile =
        argc > 1 ? argv[1] : "tienda.dat";

    try {
        FileSystem filesystem(inventoryFile);

        int server = socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

        if (server < 0) {
            throw std::runtime_error(
                "No se pudo crear el socket"
            );
        }

        int reuse = 1;

        setsockopt(
            server,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)
        );

        sockaddr_in address;
        std::memset(&address, 0, sizeof(address));

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(COMMON_PORT);

        if (bind(
                server,
                reinterpret_cast<sockaddr *>(&address),
                sizeof(address)
            ) < 0) {
            close(server);
            throw std::runtime_error(
                "No se pudo utilizar el puerto 9090"
            );
        }

        if (listen(server, 5) < 0) {
            close(server);
            throw std::runtime_error(
                "No se pudo iniciar la escucha"
            );
        }

        std::cout
            << "====================================\n"
            << " SERVIDOR MANCOMUNADO - ISLA B\n"
            << "====================================\n"
            << "Puerto: " << COMMON_PORT << "\n"
            << "Inventario: " << inventoryFile << "\n"
            << std::endl;

        unsigned int messageNumber = 1;

        while (true) {
            int client = accept(
                server,
                nullptr,
                nullptr
            );

            if (client < 0) {
                continue;
            }

            timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;

            setsockopt(
                client,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout,
                sizeof(timeout)
            );

            std::string request;
            char character;
            bool complete = false;

            while (request.size() < BUFFER_SIZE - 1) {
                ssize_t bytesRead = recv(
                    client,
                    &character,
                    1,
                    0
                );

                if (bytesRead <= 0) {
                    break;
                }

                if (character == '\n') {
                    complete = true;
                    break;
                }

                if (character != '\r') {
                    request += character;
                }
            }

            std::string response = "02/100";

            if (complete) {
                std::cout
                    << "\n[MANCOMUNADO] Solicitud: "
                    << request << std::endl;

                try {
                    response = processRequest(
                        filesystem,
                        request,
                        messageNumber
                    );
                } catch (const std::exception &error) {
                    std::cerr
                        << "Error: "
                        << error.what() << std::endl;
                }
            }

            std::cout
                << "[MANCOMUNADO] Respuesta: "
                << response << std::endl;

            response += "\n";

            size_t sent = 0;

            while (sent < response.size()) {
                ssize_t bytesSent = send(
                    client,
                    response.data() + sent,
                    response.size() - sent,
                    0
                );

                if (bytesSent <= 0) {
                    break;
                }

                sent += static_cast<size_t>(bytesSent);
            }

            close(client);
        }

        close(server);

    } catch (const std::exception &error) {
        std::cerr
            << "Error del servidor mancomunado: "
            << error.what() << std::endl;

        return 1;
    }

    return 0;
}
