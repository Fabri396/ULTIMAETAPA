
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>

#include "FileSystem.h"
#include "SIQPProtocol.h"

const std::string CLIENT_ID = "CLI-01";
const std::string INTERMEDIARY_ID = "INT-01";
const std::string SERVER_ID = "SI-01";


std::vector<std::string> splitMessage(
    const std::string &message,
    char delimiter
) {
    std::vector<std::string> fields;
    std::string field;

    for (char character : message) {
        if (character == delimiter) {
            fields.push_back(field);
            field.clear();
        } else {
            field += character;
        }
    }

    // Preserve the last field, even when it is empty.
    fields.push_back(field);

    return fields;
}

std::string generateMessageId(unsigned int sequence) {
    std::ostringstream stream;

    stream << std::setw(5)
           << std::setfill('0')
           << sequence;

    return stream.str();
}

class Simulation {
private:
    FileSystem filesystem;
    unsigned int sequence;
    bool stepByStep;

    void pause() {
        if (!stepByStep) {
            return;
        }

        std::cout << "\nPresiona ENTER para continuar...";
        std::string input;
        std::getline(std::cin, input);
    }

    void showStep(
        const std::string &component,
        const std::string &action,
        const std::string &details
    ) {
        std::cout << "\n----------------------------------------\n";
        std::cout << "[" << component << "] " << action << "\n";

        if (!details.empty()) {
            std::cout << details << "\n";
        }

        std::cout << "----------------------------------------\n";
        pause();
    }

    std::string buildRequest(
        int messageType,
        const std::string &body
    ) {
        std::ostringstream stream;

        stream << "SIQP/1.0"
               << "|" << messageType
               << "|" << generateMessageId(sequence++)
               << "|" << CLIENT_ID
               << "|" << SERVER_ID
               << "|" << body;

        return stream.str();
    }

    bool parseCommand(
        const std::string &command,
        int &messageType,
        std::string &body
    ) {
        std::istringstream stream(command);

        std::string operation;
        std::string category;
        std::string product;
        std::string extra;

        stream >> operation;

        if (operation == "help") {
            messageType = 10;
            body = "";
        }
        else if (operation == "inventory") {
            messageType = 12;
            body = "";
        }
        else if (operation == "have") {
            if (!(stream >> category)) {
                std::cout << "Uso: have <categoria>\n";
                return false;
            }

            messageType = 14;
            body = "categoria=" + category;
        }
        else if (operation == "stock") {
            if (!(stream >> category >> product)) {
                std::cout << "Uso: stock <categoria> <producto>\n";
                return false;
            }

            messageType = 16;
            body = "categoria=" + category +
                   ";producto=" + product;
        }
        else if (operation == "info") {
            if (!(stream >> category >> product)) {
                std::cout << "Uso: info <categoria> <producto>\n";
                return false;
            }

            messageType = 18;
            body = "categoria=" + category +
                   ";producto=" + product;
        }
        else {
            std::cout << "Comando desconocido.\n";
            return false;
        }

        if (stream >> extra) {
            std::cout << "Error: demasiados argumentos.\n";
            return false;
        }

        return true;
    }

    std::string processServerRequest(
        const std::string &request
    ) {
        showStep(
            "SERVIDOR " + SERVER_ID,
            "Solicitud recibida",
            request
        );

        showStep(
            "SERVIDOR " + SERVER_ID,
            "Procesando protocolo SIQP/1.0",
            "Validando el mensaje y sus parametros."
        );

        showStep(
            "SERVIDOR " + SERVER_ID,
            "Consultando FileSystem",
            "Archivo: tienda.dat\n"
            "Se utiliza la implementacion real de FileSystem."
        );

        std::string response = SIQPProtocol::processRequest(
            request,
            filesystem,
            SERVER_ID
        );

        showStep(
            "SERVIDOR " + SERVER_ID,
            "Respuesta generada",
            response
        );

        return response;
    }

    std::string processIntermediary(
        const std::string &request
    ) {
        showStep(
            "INTERMEDIARIO " + INTERMEDIARY_ID,
            "Solicitud recibida desde el cliente",
            request
        );

        std::vector<std::string> fields =
            splitMessage(request, '|');

        if (fields.size() != 6) {
            throw std::runtime_error(
                "Mensaje SIQP incompleto"
            );
        }

        if (fields[0] != "SIQP/1.0") {
            throw std::runtime_error(
                "Version SIQP no soportada"
            );
        }

        if (fields[4] != SERVER_ID) {
            throw std::runtime_error(
                "Servidor destino desconocido"
            );
        }

        showStep(
            "INTERMEDIARIO " + INTERMEDIARY_ID,
            "Seleccionando servidor de inventario",
            "Destino: " + fields[4] +
            "\nMensaje: " + fields[2] +
            "\nRuta local disponible."
        );

        showStep(
            "INTERMEDIARIO " + INTERMEDIARY_ID,
            "Reenviando solicitud al servidor",
            request
        );

        std::string response = processServerRequest(request);

        showStep(
            "INTERMEDIARIO " + INTERMEDIARY_ID,
            "Respuesta recibida del servidor",
            response
        );

        std::vector<std::string> responseFields =
            splitMessage(response, '|');

        if (responseFields.size() != 6) {
            throw std::runtime_error(
                "Respuesta SIQP incompleta"
            );
        }

        if (responseFields[0] != "SIQP/1.0") {
            throw std::runtime_error(
                "Version de respuesta incorrecta"
            );
        }

        if (responseFields[2] != fields[2]) {
            throw std::runtime_error(
                "ID de mensaje no coincide"
            );
        }

        if (responseFields[3] != SERVER_ID ||
            responseFields[4] != CLIENT_ID) {
            throw std::runtime_error(
                "Origen o destino de respuesta incorrecto"
            );
        }

        showStep(
            "INTERMEDIARIO " + INTERMEDIARY_ID,
            "Enviando respuesta al cliente",
            "Identificador verificado: " + responseFields[2]
        );

        return response;
    }

    void displayResult(const std::string &response) {
        std::vector<std::string> fields =
            splitMessage(response, '|');

        std::cout << "\n========================================\n";
        std::cout << "           RESULTADO FINAL\n";
        std::cout << "========================================\n";

        if (fields.size() != 6) {
            std::cout << "Respuesta invalida.\n";
            return;
        }

        std::cout << "ID de mensaje: " << fields[2] << "\n";
        std::cout << "Tipo de respuesta: " << fields[1] << "\n";
        std::cout << "Contenido: " << fields[5] << "\n";
        std::cout << "========================================\n";
    }

public:
    Simulation()
        : filesystem("tienda.dat"),
          sequence(1),
          stepByStep(true) {
    }

    void execute(const std::string &command) {
        int messageType = 0;
        std::string body;

        if (!parseCommand(command, messageType, body)) {
            return;
        }

        std::string request = buildRequest(
            messageType,
            body
        );

        showStep(
            "CLIENTE " + CLIENT_ID,
            "Generando solicitud",
            "Comando: " + command +
            "\nMensaje SIQP:\n" + request
        );

        showStep(
            "CLIENTE " + CLIENT_ID,
            "Enviando solicitud al intermediario",
            "Destino logico: " + INTERMEDIARY_ID
        );

        std::string response = processIntermediary(request);

        showStep(
            "CLIENTE " + CLIENT_ID,
            "Respuesta recibida",
            response
        );

        displayResult(response);
    }

    void setStepByStep(bool enabled) {
        stepByStep = enabled;
    }

    bool isStepByStep() const {
        return stepByStep;
    }
};

int main() {
    try {
        Simulation simulation;

        std::cout << "========================================\n";
        std::cout << "       SIMULACION SIQP/1.0\n";
        std::cout << "========================================\n";
        std::cout << "Cliente:       CLI-01\n";
        std::cout << "Intermediario: INT-01\n";
        std::cout << "Servidor:      SI-01\n";
        std::cout << "Almacenamiento: tienda.dat\n";
        std::cout << "Ejecucion: un solo hilo\n";
        std::cout << "========================================\n";

        std::cout << "\nComandos disponibles:\n";
        std::cout << "  help\n";
        std::cout << "  inventory\n";
        std::cout << "  have <categoria>\n";
        std::cout << "  stock <categoria> <producto>\n";
        std::cout << "  info <categoria> <producto>\n";
        std::cout << "  mode step\n";
        std::cout << "  mode auto\n";
        std::cout << "  exit\n";

        std::string command;

        while (true) {
            std::cout << "\nsim> ";

            if (!std::getline(std::cin, command)) {
                break;
            }

            if (command == "exit") {
                break;
            }

            if (command == "mode step") {
                simulation.setStepByStep(true);
                std::cout << "Modo paso a paso activado.\n";
                continue;
            }

            if (command == "mode auto") {
                simulation.setStepByStep(false);
                std::cout << "Modo automatico activado.\n";
                continue;
            }

            if (command.empty()) {
                continue;
            }

            try {
                simulation.execute(command);
            } catch (const std::exception &error) {
                std::cerr << "\n[ERROR] "
                          << error.what() << "\n";
            }
        }

        std::cout << "\nSimulacion finalizada.\n";
        return 0;

    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
