
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>
#include <cerrno>
#include <csignal>
#include <cstring>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "Socket.h"
#include "FileSystem.h"
#include "SIQPProtocol.h"
#include "SSLSocket.h"

constexpr int PORT = 2027;
constexpr size_t BUFFER_SIZE = 8192;

void handleClient(VSocket* client, FileSystem& filesystem) {
    char buffer[BUFFER_SIZE];

    try {
        std::memset(buffer, 0, sizeof(buffer));

        size_t bytesRead = client->Read(
            buffer,
            sizeof(buffer) - 1
        );

        if (bytesRead == 0) {
            return;
        }

        std::string request(buffer, bytesRead);

        std::cout
            << "[PID " << getpid() << "] Solicitud: "
            << request << std::endl;

        std::string response =
            SIQPProtocol::processRequest(
                request,
                filesystem,
                "SI-01"
            );

        client->Write(
            response.c_str(),
            response.size()
        );

        std::cout
            << "[PID " << getpid() << "] Respuesta: "
            << response << std::endl;

    } catch (const std::exception& error) {
        std::cerr
            << "[PID " << getpid() << "] Error: "
            << error.what() << std::endl;
    }
}

int main() {
    // SIGCHLD evita que los procesos hijos terminados
    // permanezcan como zombies en Linux.
    struct sigaction action{};
    action.sa_handler = SIG_IGN;
    action.sa_flags = SA_NOCLDWAIT;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGCHLD, &action, nullptr) < 0) {
        std::perror("sigaction");
        return 1;
    }

    // Cada proceso hijo abre su propia instancia de
    // FileSystem para evitar compartir el estado del fstream.
    std::unique_ptr<VSocket> server;

    try {
         server.reset(    
            new SSLSocket(
               "certs/server.crt",
               "certs/server.key",
               false
            )
         );

        if (server->Bind(PORT) < 0) {
            throw std::runtime_error(
                "No se pudo enlazar el puerto"
            );
        }

        if (server->MarkPassive(10) < 0) {
            throw std::runtime_error(
                "No se pudo iniciar la escucha"
            );
        }

        std::cout
            << "====================================\n"
            << "    FORK MIRROR SERVER - SIQP/1.0\n"
            << "====================================\n"
            << "Puerto: " << PORT << "\n"
            << "Servidor: SI-01\n"
            << "Almacenamiento: tienda.dat\n"
            << "Modo: un proceso por conexion\n"
            << std::endl;

        while (true) {
            VSocket* client = nullptr;

            try {
                client = server->AcceptConnection();
            } catch (const std::exception& error) {
                std::cerr
                    << "Error aceptando conexion: "
                    << error.what() << std::endl;
                continue;
            }

            if (client == nullptr) {
                continue;
            }

            pid_t childPid = fork();

            if (childPid < 0) {
                std::cerr
                    << "Error al crear proceso: "
                    << std::strerror(errno)
                    << std::endl;

                client->Close();
                delete client;
                continue;
            }

            if (childPid == 0) {
                // Proceso hijo: no necesita el socket
                // que escucha nuevas conexiones.
                server->Close();

                int exitCode = 0;

                try {
                    FileSystem filesystem("tienda.dat");
                    handleClient(client, filesystem);
                } catch (const std::exception& error) {
                    std::cerr
                        << "[PID " << getpid()
                        << "] Error de almacenamiento: "
                        << error.what() << std::endl;
                    exitCode = 1;
                }

                client->Close();
                delete client;

                _exit(exitCode);
            }

            // Proceso padre: conserva el socket servidor,
            // pero cierra su copia de la conexion aceptada.
            client->Close();
            delete client;
        }

    } catch (const std::exception& error) {
        std::cerr
            << "Error del servidor: "
            << error.what() << std::endl;
        return 1;
    }

    return 0;
}
