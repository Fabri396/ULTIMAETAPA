#include "AutoDiscovery.h"
#include <sys/wait.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <cerrno>
#include <climits>
#include <chrono>
#include <atomic>
#include <vector>
#include <fstream>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "Socket.h"
#include "FileSystem.h"
#include "SIQPProtocol.h"
#include "SSLSocket.h"
#include "AuditLog.h"

namespace {
constexpr size_t BUFFER_SIZE = 8192;
std::mutex inventoryMutex;

struct Config {
    int port = 2028;
    std::string id = "SI-01";
    std::string inventory = "";
    std::string certificate = "certs/server.crt";
    std::string key = "certs/server.key";
    std::string intermediaryHost;
    int intermediaryPort = 2027;
    std::string advertiseHost;
};

int parsePort(const std::string& value) {
    char* end = nullptr;
    errno = 0;
    long number = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' || number < 1 || number > 65535) {
        throw std::invalid_argument("Puerto invalido: " + value);
    }
    return static_cast<int>(number);
}

Config parseArguments(int argc, char** argv) {
    Config config;
    for (int index = 1; index < argc; index++) {
        std::string argument = argv[index];
        if (argument == "--help") {
            std::cout << "Uso: " << argv[0]
                      << " [--id SI-01] [--port 2028] [--inventario tienda.dat]"
                      << " [--cert certs/server.crt] [--key certs/server.key]"
                      << " [--intermediario IP:2027] [--host IP_VISIBLE]\n"
                      << "Sin --intermediario descubre INT-01 automaticamente (UDP 2026).\n";
            std::exit(0);
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument("Falta valor para " + argument);
        }
        std::string value = argv[++index];
        if (value.empty()) throw std::invalid_argument("Valor vacio para " + argument);
        if (argument == "--id") config.id = value;
        else if (argument == "--port") config.port = parsePort(value);
        else if (argument == "--inventario") config.inventory = value;
        else if (argument == "--cert") config.certificate = value;
        else if (argument == "--key") config.key = value;
        else if (argument == "--host") config.advertiseHost = value;
        else if (argument == "--intermediario") {
            size_t colon = value.rfind(':');
            if (colon == std::string::npos) throw std::invalid_argument("Use IP:PUERTO");
            config.intermediaryHost = value.substr(0, colon);
            config.intermediaryPort = parsePort(value.substr(colon + 1));
        }
        else throw std::invalid_argument("Argumento desconocido: " + argument);
    }
    return config;
}

std::string detectAddress(const std::string& host, int port) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if(fd<0) throw std::runtime_error("No se pudo detectar IP local");
    sockaddr_in peer{};peer.sin_family=AF_INET;peer.sin_port=htons(port);
    if(inet_pton(AF_INET,host.c_str(),&peer.sin_addr)!=1) {
        addrinfo hints{};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_DGRAM;
        addrinfo* result=nullptr;
        if(getaddrinfo(host.c_str(),nullptr,&hints,&result)!=0) {close(fd);throw std::runtime_error("No se pudo resolver DNS del intermediario");}
        peer.sin_addr=((sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }
    if(connect(fd,(sockaddr*)&peer,sizeof(peer))!=0){close(fd);throw std::runtime_error("No hay ruta hacia intermediario");}
    sockaddr_in local{};socklen_t size=sizeof(local);
    if(getsockname(fd,(sockaddr*)&local,&size)!=0){close(fd);throw std::runtime_error("No se pudo determinar IP");}
    char buffer[INET_ADDRSTRLEN]{};inet_ntop(AF_INET,&local.sin_addr,buffer,sizeof(buffer));close(fd);
    return buffer;
}

void registrationLoop(const Config& config, FileSystem& filesystem) {
    unsigned long sequence = 0;
    while (true) {
        try {
            std::vector<std::string> categories;
            {
                std::lock_guard<std::mutex> lock(inventoryMutex);
                categories = filesystem.listCategories();
            }
            std::string names;
            for (const auto& category : categories) {
                if (!names.empty()) names += ",";
                names += SIQPProtocol::escapeValue(category);
            }
            SIQPMessage message;
            message.version = "SIQP/1.0";
            message.type = 40;
            message.messageId = std::to_string(++sequence);
            message.source = config.id;
            message.destination = "INT-01";
            message.body = "host=" + config.advertiseHost + ";puerto=" +
                           std::to_string(config.port) + ";categorias=" + names;
            SSLSocket connection(false);
            connection.ConnectVerified(config.intermediaryHost.c_str(), config.intermediaryPort, "INT-01");
            std::string raw = SIQPProtocol::buildMessage(message);
            connection.Write(raw.c_str(), raw.size());
            char buffer[8192] = {};
            size_t count = connection.Read(buffer, sizeof(buffer) - 1);
            if (!count || SIQPProtocol::parseMessage(std::string(buffer, count)).type != 41)
                throw std::runtime_error("Registro rechazado");
            std::cout << "[" << config.id << "] Registro actualizado" << std::endl;
            // Registros periodicos exitosos no se guardan para evitar llenar la bitacora.
        } catch (const std::exception& error) {
            std::cerr << "[" << config.id << "] Registro pendiente: " << error.what() << std::endl;
            AuditLog::write(config.id, "ERROR_REGISTRO", error.what());
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void handleClient(std::unique_ptr<VSocket> client, FileSystem& filesystem, const std::string& serverId) {
    try {
        char buffer[BUFFER_SIZE] = {};
        const size_t count = client->Read(buffer, sizeof(buffer) - 1);
        if (count == 0) return;
        const std::string request(buffer, count);
        AuditLog::write(serverId, "SOLICITUD", request);
        std::string response;
        {
            std::lock_guard<std::mutex> lock(inventoryMutex);
            response = SIQPProtocol::processRequest(request, filesystem, serverId);
        }
        AuditLog::write(serverId, "RESPUESTA", response);
        client->Write(response.c_str(), response.size());
        std::cout << "[" << serverId << "] Solicitud: " << request
                  << "\n[" << serverId << "] Respuesta: " << response << std::endl;
    } catch (const std::exception& error) {
        std::cerr << "[" << serverId << "] Error en cliente: " << error.what() << std::endl;
        AuditLog::write(serverId, "ERROR_CLIENTE", error.what());
    }
}
}

int main(int argc, char** argv) {
    try {
        Config config = parseArguments(argc, argv);
        if(config.inventory.empty())config.inventory=config.id+".dat";
        // Descubrimiento automático: respuesta UDP incluye el certificado CA publico.
        // En la primera conexion esta confianza es TOFU (no autenticada).
        if(config.intermediaryHost.empty()) {
            auto found=AutoDiscovery::find();
            config.intermediaryHost=found.ip;
            config.intermediaryPort=2027;
            std::ifstream previous("certs/siqp-trust.crt",std::ios::binary);
            std::string old((std::istreambuf_iterator<char>(previous)),std::istreambuf_iterator<char>());
            // Conservamos el anclaje existente: nunca sustituir automaticamente CA distinta.
            std::string candidateCert="certs/"+config.id+".crt";
            std::string candidateKey="certs/"+config.id+".key";
            if(!old.empty() && old!=found.ca &&
               (access(candidateCert.c_str(),F_OK)==0 || access(candidateKey.c_str(),F_OK)==0))
                throw std::runtime_error("CA diferente: bodega ya inscrita, no se reemplaza confianza automaticamente");
            if(old!=found.ca){
                mkdir("certs",0700);
                std::ofstream out("certs/siqp-trust.crt",std::ios::binary);out<<found.ca;
                if(!out)throw std::runtime_error("No se pudo guardar CA descubierta");
                std::cerr<<"[ADVERTENCIA] Confianza TLS inicial obtenida por UDP sin autenticar (TOFU). Solo laboratorio aislado.\n";
            }
            std::cout<<"["<<config.id<<"] Intermediario descubierto: "<<config.intermediaryHost<<":2027\n";
        }
        // Creacion de identidad unica para esta bodega sin pedir token.
        std::string certPath="certs/"+config.id+".crt", keyPath="certs/"+config.id+".key";
        if(access(certPath.c_str(),F_OK)!=0||access(keyPath.c_str(),F_OK)!=0){
            pid_t pid=fork();
            if(pid==0){execl("./TLSManager.out","TLSManager.out","enroll","--id",config.id.c_str(),"--host",config.intermediaryHost.c_str(),"--auto","yes",(char*)nullptr);_exit(127);}
            if(pid<0)throw std::runtime_error("No se pudo ejecutar TLSManager");
            int status=0;waitpid(pid,&status,0);
            if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)throw std::runtime_error("No se pudo inscribir la bodega automaticamente");
        }
        config.certificate=certPath;
        config.key=keyPath;
        setenv("SIQP_CA_FILE","certs/siqp-trust.crt",1);
        setenv("SIQP_CLIENT_CERT",certPath.c_str(),1);
        setenv("SIQP_CLIENT_KEY",keyPath.c_str(),1);
        if (!config.intermediaryHost.empty() && config.advertiseHost.empty())
            config.advertiseHost=detectAddress(config.intermediaryHost,config.intermediaryPort);
        if (config.advertiseHost.empty()) config.advertiseHost="127.0.0.1";
        FileSystem filesystem(config.inventory);
        std::unique_ptr<VSocket> server(new SSLSocket(config.certificate.c_str(), config.key.c_str(), false));
        server->Bind(config.port);
        server->MarkPassive(20);
        if (!config.intermediaryHost.empty())
            std::thread(registrationLoop, std::cref(config), std::ref(filesystem)).detach();
        std::cout << "Bodega " << config.id << " escuchando en 0.0.0.0:" << config.port
                  << " | Inventario: " << config.inventory << std::endl;
        while (true) {
            try {
                std::unique_ptr<VSocket> client(server->AcceptConnection());
                std::thread(handleClient, std::move(client), std::ref(filesystem), config.id).detach();
            } catch (const std::exception& error) {
                std::cerr << "Error aceptando conexion: " << error.what() << std::endl;
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "Error iniciando bodega: " << error.what() << std::endl;
        return 1;
    }
}
