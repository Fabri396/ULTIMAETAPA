
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <iomanip>
#include <memory>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <fstream>
#include <cerrno>
#include <sys/stat.h>
#include "AutoDiscovery.h"

#include "Socket.h"
#include "SSLSocket.h"


#define PORT 2027
#define BUFSIZE 8192

// Descubre el intermediario en cada solicitud: tolera cambios de IP tras reinicios.
// La primera CA descubierta se conserva (TOFU); nunca se sustituye silenciosamente.
std::string findIntermediary() {
    const char* manual = std::getenv("SIQP_INTERMEDIARY");
    if (manual && *manual) return manual;
    AutoDiscovery::Server found = AutoDiscovery::find();
    const std::string path = "certs/siqp-trust.crt";
    std::ifstream file(path.c_str(), std::ios::binary);
    const std::string saved((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    if (!saved.empty() && saved != found.ca)
        throw std::runtime_error("La CA anunciada difiere de la CA confiable. No se reemplaza automaticamente.");
    if (saved.empty()) {
        if (mkdir("certs", 0700) != 0 && errno != EEXIST)
            throw std::runtime_error("No se pudo crear certs/");
        std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
        if (!out || !(out << found.ca))
            throw std::runtime_error("No se pudo guardar certs/siqp-trust.crt");
        std::cerr << "[ADVERTENCIA] Primera confianza TLS recibida por UDP sin autenticar; usar solo en laboratorio aislado.\n";
    }
    return found.ip;
}
const std::string CLIENT_ID = "CLI-01";
const std::string SERVER_ID = "SI-01";

std::string escapeValue(const std::string& value) {
    std::string result;

    for (char character : value) {
        if (character == '|' ||
            character == ';' ||
            character == '=' ||
            character == ',' ||
            character == '\\') {
            result += '\\';
        }

        result += character;
    }

    return result;
}

std::string unescapeValue(const std::string& value) {
    std::string result;
    bool escaped = false;

    for (char character : value) {
        if (escaped) {
            result += character;
            escaped = false;
        } else if (character == '\\') {
            escaped = true;
        } else {
            result += character;
        }
    }

    if (escaped) {
        throw std::runtime_error("Escape incompleto");
    }

    return result;
}

std::string buildRequest(
    const std::string& command,
    int messageNumber
) {
    std::stringstream input(command);

    std::string operation;
    std::string category;
    std::string product;
    std::string extra;

    input >> operation;

    int messageType = 0;
    std::string body;

    if (operation == "help") {
        messageType = 10;

    } else if (operation == "inventory") {
        messageType = 12;

    } else if (operation == "have") {
        if (!(input >> category)) {
            throw std::runtime_error(
                "Uso: have <categoria>"
            );
        }

        messageType = 14;
        body = "categoria=" + escapeValue(category);

    } else if (operation == "stock") {
        if (!(input >> category >> product)) {
            throw std::runtime_error(
                "Uso: stock <categoria> <producto>"
            );
        }

        messageType = 16;

        body =
            "categoria=" + escapeValue(category) +
            ";producto=" + escapeValue(product);

    } else if (operation == "info") {
        if (!(input >> category >> product)) {
            throw std::runtime_error(
                "Uso: info <categoria> <producto>"
            );
        }

        messageType = 18;

        body =
            "categoria=" + escapeValue(category) +
            ";producto=" + escapeValue(product);

    } else if (operation == "buy") {
        std::string quantity;
        if (!(input >> category >> product >> quantity))
            throw std::runtime_error("Uso: buy <categoria> <producto> <cantidad>");
        if (quantity.empty() || quantity.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("La cantidad de compra debe ser un entero mayor que cero.");
        try {
            const unsigned long long parsed = std::stoull(quantity);
            if (parsed == 0 || parsed > 4294967295ULL)
                throw std::runtime_error("La cantidad de compra debe ser mayor que cero y no exceder 4294967295.");
        } catch (const std::invalid_argument&) {
            throw std::runtime_error("La cantidad de compra debe ser un entero mayor que cero.");
        } catch (const std::out_of_range&) {
            throw std::runtime_error("La cantidad de compra es demasiado grande.");
        }
        messageType = 60;
        body = "categoria=" + escapeValue(category) + ";producto=" + escapeValue(product) +
               ";cantidad=" + escapeValue(quantity);
    } else if (operation == "addcategory") {
        std::string warehouse;
        if (!(input >> warehouse >> category)) throw std::runtime_error("Uso: addcategory <bodega> <categoria>");
        messageType = 50;
        body = "bodega=" + escapeValue(warehouse) + ";categoria=" + escapeValue(category);
    } else if (operation == "addproduct") {
        std::string warehouse, quantity, price, location, description;
        if (!(input >> warehouse >> category >> product >> quantity >> price >> location >> description))
            throw std::runtime_error("Uso: addproduct <bodega> <categoria> <producto> <cantidad> <precio> <ubicacion> <descripcion> (sin espacios)");
        messageType = 52;
        body = "bodega=" + escapeValue(warehouse) + ";categoria=" + escapeValue(category) +
               ";producto=" + escapeValue(product) + ";cantidad=" + escapeValue(quantity) +
               ";precio=" + escapeValue(price) + ";ubicacion=" + escapeValue(location) +
               ";descripcion=" + escapeValue(description);
    } else if (operation == "addstock") {
        std::string warehouse, quantity;
        if (!(input >> warehouse >> category >> product >> quantity))
            throw std::runtime_error("Uso: addstock <bodega> <categoria> <producto> <cantidad>");
        messageType = 54;
        body = "bodega=" + escapeValue(warehouse) + ";categoria=" + escapeValue(category) +
               ";producto=" + escapeValue(product) + ";cantidad=" + escapeValue(quantity);
    } else {
        throw std::runtime_error(
            "Comando desconocido. Escribe help."
        );
    }

    if (input >> extra) {
        throw std::runtime_error(
            "Demasiados argumentos para el comando"
        );
    }

    std::ostringstream messageId;

    messageId << std::setfill('0')
              << std::setw(5)
              << messageNumber;

    std::ostringstream request;

    request << "SIQP/1.0|"
            << std::setfill('0')
            << std::setw(2)
            << messageType
            << "|"
            << messageId.str()
            << "|"
            << CLIENT_ID
            << "|"
            << SERVER_ID
            << "|"
            << body;

    return request.str();
}

std::map<std::string, std::string> parseBody(
    const std::string& body
) {
    std::map<std::string, std::string> attributes;

    std::string entry;
    bool escaped = false;

    auto addEntry = [&]() {
        if (entry.empty()) {
            return;
        }

        size_t separator = std::string::npos;
        bool escapeNext = false;

        for (size_t index = 0; index < entry.size(); ++index) {
            if (entry[index] == '=' && !escapeNext) {
                separator = index;
                break;
            }

            if (entry[index] == '\\' && !escapeNext) {
                escapeNext = true;
            } else {
                escapeNext = false;
            }
        }

        if (separator != std::string::npos) {
            std::string key = entry.substr(0, separator);
            std::string value = entry.substr(separator + 1);

            attributes[key] = unescapeValue(value);
        }

        entry.clear();
    };

    for (char character : body) {
        if (character == ';' && !escaped) {
            addEntry();
        } else {
            entry += character;
        }

        if (character == '\\' && !escaped) {
            escaped = true;
        } else {
            escaped = false;
        }
    }

    addEntry();

    return attributes;
}

std::string getAttribute(
    const std::map<std::string, std::string>& attributes,
    const std::string& key
) {
    auto found = attributes.find(key);

    if (found == attributes.end()) {
        return "";
    }

    return found->second;
}

void showResponse(const std::string& response) {
    std::stringstream input(response);

    std::string version;
    std::string typeText;
    std::string messageId;
    std::string source;
    std::string destination;
    std::string body;

    std::getline(input, version, '|');
    std::getline(input, typeText, '|');
    std::getline(input, messageId, '|');
    std::getline(input, source, '|');
    std::getline(input, destination, '|');
    std::getline(input, body);

    if (version != "SIQP/1.0") {
        std::cout << "Respuesta inesperada: "
                  << response << std::endl;
        return;
    }

    int messageType = 0;

    try {
        messageType = std::stoi(typeText);
    } catch (const std::exception&) {
        std::cout << "Respuesta invalida: "
                  << response << std::endl;
        return;
    }

    std::map<std::string, std::string> attributes =
        parseBody(body);

    switch (messageType) {
        case 11:
            std::cout
                << "Comandos disponibles:\n"
                << "  help\n"
                << "  inventory\n"
                << "  have <categoria>\n"
                << "  stock <categoria> <producto>\n"
                << "  info <categoria> <producto>\n"
                << "  buy <categoria> <producto> <cantidad>\n"
                << "  addcategory <bodega> <categoria>\n"
                << "  addproduct <bodega> <categoria> <producto> <cantidad> <precio> <ubicacion> <descripcion>\n"
                << "  addstock <bodega> <categoria> <producto> <cantidad>\n"
                << "  exit\n";
            break;

        case 13:
            std::cout << "Categorias: "
                      << getAttribute(attributes, "categorias")
                      << std::endl;
            break;

        case 15:
            std::cout << "Productos: "
                      << getAttribute(attributes, "productos")
                      << std::endl;
            break;

        case 17:
            std::cout << "Cantidad: "
                      << getAttribute(attributes, "cantidad")
                      << std::endl;
            break;

        case 19:
            std::cout
                << "Cantidad: "
                << getAttribute(attributes, "cantidad")
                << "\nPrecio: "
                << getAttribute(attributes, "precio")
                << "\nUbicacion: "
                << getAttribute(attributes, "ubicacion")
                << "\nDescripcion: "
                << getAttribute(attributes, "descripcion")
                << std::endl;
            break;

        case 61:
            std::cout << "Compra realizada. Unidades: " << getAttribute(attributes, "cantidad")
                      << " | Precio unitario: " << getAttribute(attributes, "precio")
                      << " | Total: " << getAttribute(attributes, "total")
                      << " | Existencias restantes: " << getAttribute(attributes, "restante") << std::endl;
            break;
        case 62:
            std::cout << "Error: existencias insuficientes. Disponible: "
                      << getAttribute(attributes, "disponible") << std::endl;
            break;
        case 51:
            std::cout << "Categoria creada correctamente." << std::endl;
            break;
        case 53:
            std::cout << "Producto creado correctamente." << std::endl;
            break;
        case 55:
            std::cout << "Existencias actualizadas. Cantidad: " << getAttribute(attributes, "cantidad") << std::endl;
            break;
        case 56:
            std::cout << "No se realizo el cambio: " << getAttribute(attributes, "detalle") << std::endl;
            break;
        case 30:
            std::cout << "Error: categoria no encontrada."
                      << std::endl;
            break;

        case 31:
            std::cout << "Error: producto no encontrado."
                      << std::endl;
            break;

        case 101:
            std::cout << "Error: formato SIQP invalido."
                      << std::endl;
            break;

        case 102:
            std::cout << "Error: destino no disponible."
                      << std::endl;
            break;

        case 103:
            std::cout << "Error: version no soportada."
                      << std::endl;
            break;

        case 105:
            std::cout << "Error: tipo de mensaje no soportado."
                      << std::endl;
            break;

        case 106:
            std::cout << "Error: parametros invalidos."
                      << std::endl;
            break;

        case 109:
            std::cout << "Error: almacenamiento."
                      << std::endl;
            break;

        default:
            std::cout << "Respuesta SIQP:\n"
                      << response << std::endl;
            break;
    }
}

std::string sendRequest(const std::string& request) {
    std::unique_ptr<VSocket> socket(
        new SSLSocket(false)
    );

    const std::string serverIp = findIntermediary();
    int result = static_cast<SSLSocket*>(socket.get())->ConnectVerified(
        serverIp.c_str(), PORT, "INT-01"
    );

    if (result < 0) {
        throw std::runtime_error(
            "No se pudo conectar al servidor"
        );
    }

    socket->Write(request.c_str());

    char buffer[BUFSIZE];
    std::memset(buffer, 0, sizeof(buffer));

    size_t bytesRead = socket->Read(
        buffer,
        BUFSIZE - 1
    );

    socket->Close();

    if (bytesRead == 0) {
        throw std::runtime_error(
            "El servidor cerro la conexion sin responder"
        );
    }

    return std::string(buffer, bytesRead);
}

int main() {
    std::string command;
    int messageNumber = 1;

    std::cout
        << "====================================\n"
        << "       CLIENTE SIQP/1.0\n"
        << "====================================\n"
        << "Servidor: descubrimiento automatico UDP 2026 (TLS INT-01)\n"
        << "Escribe help para ver los comandos.\n"
        << "Escribe exit para salir.\n"
        << std::endl;

    while (true) {
        std::cout << "siqp> " << std::flush;

        if (!std::getline(std::cin, command)) {
            break;
        }

        if (command == "exit" || command == "quit") {
            break;
        }

        if (command.empty()) {
            continue;
        }

        try {
            std::string request = buildRequest(
                command,
                messageNumber
            );

            std::string response = sendRequest(request);

            std::cout << std::endl;
            showResponse(response);
            std::cout << std::endl;

            ++messageNumber;

        } catch (const std::exception& error) {
            std::cerr
                << "Error: "
                << error.what()
                << std::endl;
        }
    }

    std::cout << "\nCliente finalizado." << std::endl;

    return 0;
}
