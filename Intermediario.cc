
#include <iostream>
#include <thread>
#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <map>
#include <mutex>
#include <chrono>
#include <cstdlib>
#include <fstream>

#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "Socket.h"
#include "SSLSocket.h"
#include "AuditLog.h"
#include <openssl/crypto.h>

#define CLIENT_PORT 2027
#define INVENTORY_PORT 2028
#define REMOTE_PORT 9090
#define BUFFER_SIZE 8192

const std::string INVENTORY_IP = "127.0.0.1";
const std::string REMOTE_IP = "127.0.0.1";
const std::string INTERMEDIARY_ID = "INT-01";

struct Warehouse {
    std::string host;
    int port;
    std::vector<std::string> categories;
    std::chrono::steady_clock::time_point lastSeen;
};
std::mutex registryMutex;
std::map<std::string, bool> warehouseOnline;
std::map<std::string, Warehouse> warehouses;


// Dashboard HTTP: consulta el registro real del intermediario.
static std::string dashboardEscape(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c < 32) out += ' ';
        else out += char(c);
    }
    return out;
}

static std::string dashboardStatus() {
    std::ostringstream json;
    json << "{\"intermediary\":{\"id\":\"" << dashboardEscape(INTERMEDIARY_ID)
         << "\",\"online\":true,\"port\":" << CLIENT_PORT << "},\"warehouses\":[";
    std::lock_guard<std::mutex> lock(registryMutex);
    bool first = true;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& item : warehouses) {
        if (!first) json << ",";
        first = false;
        const Warehouse& w = item.second;
        const bool online = warehouseOnline[item.first] &&
            now - w.lastSeen < std::chrono::seconds(16);
        json << "{\"id\":\"" << dashboardEscape(item.first) << "\",\"host\":\""
             << dashboardEscape(w.host) << "\",\"port\":" << w.port
             << ",\"online\":" << (online ? "true" : "false") << ",\"categories\":[";
        for (size_t i = 0; i < w.categories.size(); ++i) {
            if (i) json << ",";
            json << "\"" << dashboardEscape(w.categories[i]) << "\"";
        }
        json << "]}";
    }
    json << "]}";
    return json.str();
}

static std::string dashboardInventory(const std::string&, const std::string&);



static void dashboardServeClient(int fd) {
    char buffer[2048];
    const ssize_t n = recv(fd, buffer, sizeof(buffer)-1, 0);
    if (n <= 0) { close(fd); return; }
    buffer[n] = 0;
    std::istringstream request(buffer);
    std::string method, path;
    request >> method >> path;
    const bool api = path == "/api/status";
    const bool productsApi = path.compare(0,14,"/api/products?") == 0;
    
    const int status = method != "GET" ? 405 : (!api && !productsApi ? 404 : 200);
    const std::string body = status != 200 ? "Recurso no disponible" :
        (api ? dashboardStatus() : dashboardInventory(path, ""));
    const std::string header = "HTTP/1.1 " + std::to_string(status) +
        (status == 200 ? " OK" : " Error") + "\r\nContent-Type: " +
        "application/json" +
        "; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n\r\n";
    const std::string response = header + body;
    size_t offset = 0;
    while (offset < response.size()) {
        const ssize_t sent = send(fd, response.data()+offset, response.size()-offset, MSG_NOSIGNAL);
        if (sent <= 0) break;
        offset += static_cast<size_t>(sent);
    }
    close(fd);
}

static void dashboardServer() {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::cerr << "[WEB] No se pudo crear socket\n"; return; }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8082);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        std::cerr << "[WEB] No se pudo abrir puerto 8081\n";
        close(fd); return;
    }
    std::cout << "[WEB] Panel disponible en http://127.0.0.1:8082 (API interna)\n";
    for (;;) {
        const int client = accept(fd, nullptr, nullptr);
        if (client >= 0) std::thread(dashboardServeClient, client).detach();
    }
}

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

std::string buildSiqp(
    const std::string &type,
    const std::string &messageId,
    const std::string &origin,
    const std::string &destination,
    const std::string &body
) {
    return "SIQP/1.0|" + type + "|" +
           messageId + "|" +
           origin + "|" +
           destination + "|" + body;
}

std::string buildError(
    const std::vector<std::string> &request,
    const std::string &type
) {
    std::string messageId = "00000";
    std::string destination = "CLI-01";

    if (request.size() > 2 && !request[2].empty()) {
        messageId = request[2];
    }

    if (request.size() > 3 && !request[3].empty()) {
        destination = request[3];
    }

    return buildSiqp(
        type,
        messageId,
        INTERMEDIARY_ID,
        destination,
        ""
    );
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

std::string queryLocalInventory(
    const std::string &request
) {
    std::unique_ptr<VSocket> socket(
        new SSLSocket(false)
    );

    static_cast<SSLSocket*>(socket.get())->ConnectVerified(
        INVENTORY_IP.c_str(), INVENTORY_PORT, "SI-01"
    );

    socket->Write(request.c_str());

    char buffer[BUFFER_SIZE] = {0};

    size_t bytesRead = socket->Read(
        buffer,
        BUFFER_SIZE - 1
    );

    if (bytesRead == 0 || bytesRead >= BUFFER_SIZE) {
        throw std::runtime_error(
            "Respuesta local vacia o demasiado grande"
        );
    }

    std::string response(buffer, bytesRead);

    socket->Close();

    return response;
}

std::string queryRemoteIsland(
    const std::string &message
) {
    int descriptor = ::socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (descriptor < 0) {
        throw std::runtime_error(
            "No se pudo crear socket mancomunado"
        );
    }

    timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );

    setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &timeout,
        sizeof(timeout)
    );

    sockaddr_in address;
    std::memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(REMOTE_PORT);

    if (inet_pton(
            AF_INET,
            REMOTE_IP.c_str(),
            &address.sin_addr
        ) != 1) {
        close(descriptor);
        throw std::runtime_error(
            "Direccion remota invalida"
        );
    }

    if (connect(
            descriptor,
            reinterpret_cast<sockaddr *>(&address),
            sizeof(address)
        ) < 0) {
        close(descriptor);
        throw std::runtime_error(
            "No se pudo conectar a la isla remota"
        );
    }

    std::string data = message + "\n";
    size_t sent = 0;

    while (sent < data.size()) {
        ssize_t result = send(
            descriptor,
            data.data() + sent,
            data.size() - sent,
            0
        );

        if (result <= 0) {
            close(descriptor);
            throw std::runtime_error(
                "Error enviando mensaje mancomunado"
            );
        }

        sent += static_cast<size_t>(result);
    }

    std::string response;
    char character;

    while (response.size() < BUFFER_SIZE - 1) {
        ssize_t result = recv(
            descriptor,
            &character,
            1,
            0
        );

        if (result <= 0) {
            close(descriptor);
            throw std::runtime_error(
                "Error recibiendo respuesta mancomunada"
            );
        }

        if (character == '\n') {
            break;
        }

        if (character != '\r') {
            response += character;
        }
    }

    close(descriptor);

    if (response.empty()) {
        throw std::runtime_error(
            "Respuesta mancomunada vacia"
        );
    }

    return response;
}

bool localCategoryExists(
    const std::string &category
) {
    const std::string request =
        buildSiqp(
            "12",
            "LOCAL",
            INTERMEDIARY_ID,
            "SI-01",
            ""
        );

    std::string response =
        queryLocalInventory(request);

    std::vector<std::string> fields =
        split(response, '|');

    if (fields.size() != 6 || fields[1] != "13") {
        throw std::runtime_error(
            "No se pudo consultar categorias locales"
        );
    }

    std::string categories =
        getAttribute(fields[5], "categorias");

    for (const std::string &current :
         split(categories, ',')) {
        if (lower(current) == lower(category)) {
            return true;
        }
    }

    return false;
}

std::string translateRemoteResponse(
    const std::string &response,
    const std::vector<std::string> &request
) {
    std::vector<std::string> fields =
        split(response, '/');

    const std::string &type = request[1];
    const std::string &messageId = request[2];
    const std::string &clientId = request[3];
    const std::string &serverId = request[4];

    if (fields.empty()) {
        return buildError(request, "101");
    }

    if (fields[0] == "02") {
        if (fields.size() != 2) {
            return buildError(request, "101");
        }

        if (fields[1] == "101") {
            return buildError(request, "105");
        }

        if (fields[1] == "102") {
            return buildError(request, "106");
        }

        return buildError(request, "101");
    }

    if (fields[0] == "03" && type == "14") {
        if (fields.size() != 2) {
            return buildError(request, "101");
        }

        return buildSiqp(
            "30",
            messageId,
            serverId,
            clientId,
            "categoria=" + fields[1]
        );
    }

    if (fields[0] != "01") {
        return buildError(request, "101");
    }

    if (type == "12") {
        // Empty catalogue can be returned as "01".
        if (fields.size() > 2) {
            return buildError(request, "101");
        }

        std::string categories =
            fields.size() == 2 ? fields[1] : "";

        return buildSiqp(
            "13",
            messageId,
            serverId,
            clientId,
            "categorias=" + categories
        );
    }

    if (type == "14") {
        if (fields.size() != 3) {
            return buildError(request, "101");
        }

        std::string category =
            getAttribute(request[5], "categoria");

        std::vector<std::string> products;

        if (!fields[2].empty()) {
            products = split(fields[2], ';');
        }

        size_t expectedCount;

        try {
            size_t position = 0;
            expectedCount = std::stoul(
                fields[1],
                &position
            );

            if (position != fields[1].size()) {
                return buildError(request, "101");
            }
        } catch (...) {
            return buildError(request, "101");
        }

        if (products.size() != expectedCount) {
            return buildError(request, "101");
        }

        std::string names;

        for (const std::string &entry : products) {
            std::vector<std::string> product =
                split(entry, ',');

            if (product.size() != 3 ||
                !validName(product[0])) {
                return buildError(request, "101");
            }

            if (!names.empty()) {
                names += ",";
            }

            names += product[0];
        }

        return buildSiqp(
            "15",
            messageId,
            serverId,
            clientId,
            "categoria=" + category +
            ";productos=" + names
        );
    }

    return buildError(request, "105");
}

std::string queryWarehouse(const std::string& host, int port, const std::string& request) {
    SSLSocket connection(false);
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        for (const auto& item:warehouses)
            if(item.second.host==host && item.second.port==port) {identity=item.first;break;}
    }
    if (identity.empty()) throw std::runtime_error("No existe identidad de bodega registrada");
    connection.ConnectVerified(host.c_str(), port, identity.c_str());
    connection.Write(request.c_str(), request.size());
    char buffer[BUFFER_SIZE] = {};
    size_t count = connection.Read(buffer, sizeof(buffer) - 1);
    if (count == 0) throw std::runtime_error("Respuesta vacia de bodega");
    return std::string(buffer, count);
}


static std::string urlDecode(const std::string& input) {
    std::string out;
    for (size_t i=0;i<input.size();++i) {
        if (input[i]=='%' && i+2<input.size()) {
            const std::string hex=input.substr(i+1,2);
            char* end=nullptr; long v=std::strtol(hex.c_str(),&end,16);
            if (*end==0) {out+=static_cast<char>(v);i+=2;continue;}
        }
        out+=input[i]=='+'?' ':input[i];
    }
    return out;
}
static std::string dashboardInventory(const std::string& path, const std::string&) {
    const size_t question=path.find('?');
    std::map<std::string,std::string> params;
    if(question!=std::string::npos)
        for(const auto& part:split(path.substr(question+1),'&')) {
            const size_t equal=part.find('=');
            if(equal!=std::string::npos)params[part.substr(0,equal)]=urlDecode(part.substr(equal+1));
        }
    const std::string id=params["warehouse"], category=params["category"];
    if(!validName(id)||!validName(category))return "{\"error\":\"Parametros invalidos\"}";
    Warehouse w;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        const auto found=warehouses.find(id);
        if(found==warehouses.end() || !warehouseOnline[id] ||
           std::chrono::steady_clock::now()-found->second.lastSeen>=std::chrono::seconds(16))
            return "{\"error\":\"Bodega desconectada\"}";
        w=found->second;
    }
    if(std::find(w.categories.begin(),w.categories.end(),category)==w.categories.end())
        return "{\"error\":\"Categoria no encontrada en bodega\"}";
    try {
        const std::string response=queryWarehouse(w.host,w.port,
            buildSiqp("14","WEB01","WEB-01",id,"categoria="+category));
        const auto fields=split(response,'|');
        if(fields.size()!=6 || fields[1]!="15")return "{\"error\":\"No se pudieron listar productos\"}";
        const std::string names=getAttribute(fields[5],"productos");
        std::ostringstream json;
        json<<"{\"products\":[";
        bool first=true;
        for(const auto& name:split(names,',')) {
            if(name.empty()||!validName(name))continue;
            const std::string detail=queryWarehouse(w.host,w.port,
                buildSiqp("18","WEB02","WEB-01",id,"categoria="+category+";producto="+name));
            const auto parts=split(detail,'|');
            if(parts.size()!=6||parts[1]!="19")continue;
            if(!first)json<<",";
            first=false;
            json<<"{\"name\":\""<<dashboardEscape(name)<<"\",\"stock\":\""
                <<dashboardEscape(getAttribute(parts[5],"cantidad"))<<"\",\"price\":\""
                <<dashboardEscape(getAttribute(parts[5],"precio"))<<"\",\"location\":\""
                <<dashboardEscape(getAttribute(parts[5],"ubicacion"))<<"\",\"description\":\""
                <<dashboardEscape(getAttribute(parts[5],"descripcion"))<<"\"}";
        }
        json<<"]}";return json.str();
    } catch(const std::exception& e) {
        return "{\"error\":\"No se pudo conectar con la bodega\"}";
    }
}

std::string processRegistry(const std::vector<std::string>& fields) {
    const std::string& id = fields[3];
    const std::string host = getAttribute(fields[5], "host");
    const std::string portText = getAttribute(fields[5], "puerto");
    if (!validName(id) || host.empty() || portText.empty()) return buildError(fields, "106");
    char* end = nullptr;
    long port = std::strtol(portText.c_str(), &end, 10);
    if (*end || port < 1 || port > 65535) return buildError(fields, "106");
    Warehouse entry;
    entry.host = host;
    entry.port = static_cast<int>(port);
    entry.categories = split(getAttribute(fields[5], "categorias"), ',');
    entry.lastSeen = std::chrono::steady_clock::now();
    std::string event;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        auto previous = warehouses.find(id);
        if (previous == warehouses.end()) event = "BODEGA_ALTA";
        else if (!warehouseOnline[id]) event = "BODEGA_RECONEXION";
        else if (previous->second.host != entry.host || previous->second.port != entry.port ||
                 previous->second.categories != entry.categories) event = "BODEGA_CAMBIO";
        warehouses[id] = entry;
        warehouseOnline[id] = true;
    }
    if (!event.empty()) AuditLog::write(INTERMEDIARY_ID, event,
        "bodega=" + id + ";host=" + host + ";puerto=" + portText +
        ";categorias=" + getAttribute(fields[5], "categorias"));
    std::cout << "[INT-01] Bodega registrada: " << id << " " << host << ":" << port << std::endl;
    return buildSiqp("41", fields[2], INTERMEDIARY_ID, id, "estado=registrado");
}

std::string queryRegistered(const std::vector<std::string>& fields) {
    std::vector<std::pair<std::string, Warehouse>> snapshot;
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        for (const auto& item : warehouses) {
            if (std::chrono::steady_clock::now() - item.second.lastSeen < std::chrono::seconds(16))
                snapshot.push_back(item);
        }
    }
    if (fields[1] == "42") {
        std::string body = "bodegas=";
        for (const auto& item : snapshot) {
            if (body != "bodegas=") body += ",";
            body += item.first;
        }
        return buildSiqp("43", fields[2], INTERMEDIARY_ID, fields[3], body);
    }
    if (fields[1] == "44") {
        std::string body = "rutas=";
        for (const auto& item : snapshot) for (const auto& category : item.second.categories) {
            if (category.empty()) continue;
            if (body != "rutas=") body += ",";
            body += category + ":" + item.first;
        }
        return buildSiqp("45", fields[2], INTERMEDIARY_ID, fields[3], body);
    }
    if (fields[1] == "12") {
        std::string body = "categorias=";
        for (const auto& item : snapshot) for (const auto& category : item.second.categories) {
            if (category.empty()) continue;
            if (body != "categorias=") body += ",";
            body += category;
        }
        return buildSiqp("13", fields[2], INTERMEDIARY_ID, fields[3], body);
    }
    const std::string category = getAttribute(fields[5], "categoria");
    if (!validName(category)) return buildError(fields, "106");
    bool foundCategory = false;
    std::string stockError;
    for (const auto& item : snapshot) {
        bool match = false;
        for (const auto& current : item.second.categories)
            if (lower(current) == lower(category)) match = true;
        if (!match) continue;
        foundCategory = true;
        try {
            std::vector<std::string> routed = fields;
            routed[4] = item.first;
            const std::string request = buildSiqp(routed[1], routed[2], routed[3], routed[4], routed[5]);
            std::string response = queryWarehouse(item.second.host, item.second.port, request);
            std::vector<std::string> reply = split(response, '|');
            if (fields[1] == "60" && reply.size() == 6 && reply[1] == "62") { stockError = response; continue; }
            if (reply.size() == 6 && (fields[1] == "60" ? (reply[1] == "61" || reply[1] == "62") : (reply[1] != "30" && reply[1] != "31" && reply[1] != "109")))
                return response;
        } catch (const std::exception& error) {
            std::cerr << "[INT-01] Bodega " << item.first << " no disponible: " << error.what() << std::endl;
        }
    }
    if (fields[1] == "60" && !stockError.empty()) return stockError;
    return buildSiqp(foundCategory ? "31" : "30", fields[2], INTERMEDIARY_ID,
                     fields[3], "categoria=" + category);
}


// Serialize purchases handled by this intermediary. Warehouses still validate stock.
std::mutex distributedPurchaseMutex;

std::string distributedPurchase(const std::vector<std::string>& fields) {
    std::lock_guard<std::mutex> purchaseLock(distributedPurchaseMutex);
    const std::string category=getAttribute(fields[5],"categoria");
    const std::string product=getAttribute(fields[5],"producto");
    const std::string amount=getAttribute(fields[5],"cantidad");
    if (!validName(category) || !validName(product) || amount.empty() ||
        amount.find_first_not_of("0123456789")!=std::string::npos) return buildError(fields,"106");
    unsigned long long requested=0;
    try { requested=std::stoull(amount); } catch (...) { return buildError(fields,"106"); }
    if(requested==0 || requested>4294967295ULL) return buildError(fields,"106");

    struct Offer { std::string id; Warehouse warehouse; unsigned long long stock; unsigned long long price; };
    std::vector<Offer> offers;
    {
        std::lock_guard<std::mutex> registryLock(registryMutex);
        for(const auto& entry:warehouses) {
            if(!warehouseOnline[entry.first] ||
               std::chrono::steady_clock::now()-entry.second.lastSeen>=std::chrono::seconds(16)) continue;
            bool hasCategory=false;
            for(const auto& c:entry.second.categories) if(lower(c)==lower(category)) hasCategory=true;
            if(hasCategory) offers.push_back(Offer{entry.first,entry.second,0,0});
        }
    }
    unsigned long long available=0;
    std::vector<Offer> valid;
    for(auto& offer:offers) {
        try {
            const std::string response=queryWarehouse(offer.warehouse.host,offer.warehouse.port,
                buildSiqp("18",fields[2],INTERMEDIARY_ID,offer.id,
                    "categoria="+category+";producto="+product));
            const auto reply=split(response,'|');
            if(reply.size()!=6 || reply[1]!="19") continue;
            const std::string stockText=getAttribute(reply[5],"cantidad");
            const std::string priceText=getAttribute(reply[5],"precio");
            if(stockText.empty() || priceText.empty()) continue;
            offer.stock=std::stoull(stockText);
            offer.price=std::stoull(priceText);
            available+=offer.stock;
            if(offer.stock) valid.push_back(offer);
        } catch(const std::exception& e) {
            std::cerr<<"[COMPRA] No se pudo consultar "<<offer.id<<": "<<e.what()<<std::endl;
        }
    }
    if(available<requested)
        return buildSiqp("62",fields[2],INTERMEDIARY_ID,fields[3],"disponible="+std::to_string(available));

    unsigned long long pending=requested, total=0, completed=0;
    std::string detail;
    for(const auto& offer:valid) {
        if(!pending) break;
        const unsigned long long take=std::min(pending,offer.stock);
        try {
            const auto reply=split(queryWarehouse(offer.warehouse.host,offer.warehouse.port,
                buildSiqp("60",fields[2],INTERMEDIARY_ID,offer.id,
                    "categoria="+category+";producto="+product+";cantidad="+std::to_string(take))),'|');
            if(reply.size()!=6 || reply[1]!="61") continue;
            const unsigned long long charged=std::stoull(getAttribute(reply[5],"total"));
            pending-=take;completed+=take;total+=charged;
            if(!detail.empty()) detail+=",";
            detail+=offer.id+":"+std::to_string(take);
        } catch(const std::exception& e) {
            std::cerr<<"[COMPRA] Fallo ejecutando compra en "<<offer.id<<": "<<e.what()<<std::endl;
        }
    }
    if(pending) {
        // Never claim success after a partial fulfillment. A full transaction
        // protocol would be required to undo completed purchases safely.
        return buildSiqp("109",fields[2],INTERMEDIARY_ID,fields[3],
            "estado=parcial;compradas="+std::to_string(completed)+
            ";pendientes="+std::to_string(pending)+";total="+std::to_string(total)+
            ";bodegas="+detail);
    }
    return buildSiqp("61",fields[2],INTERMEDIARY_ID,fields[3],
        "producto="+product+";cantidad="+amount+";precio=variable;total="+
        std::to_string(total)+";restante="+std::to_string(available-requested)+
        ";bodegas="+detail);
}

std::string processRequest(
    const std::string &message
) {
    std::vector<std::string> fields =
        split(message, '|');

    if (fields.size() != 6) {
        return buildError(fields, "101");
    }

    if (fields[0] != "SIQP/1.0") {
        return buildError(fields, "103");
    }

    const std::string &type = fields[1];

    if (type == "50" || type == "52" || type == "54") {
        const std::string target = getAttribute(fields[5], "bodega");
        if (!validName(target)) return buildError(fields, "106");
        Warehouse warehouse;
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            auto found = warehouses.find(target);
            if (found == warehouses.end() ||
                std::chrono::steady_clock::now() - found->second.lastSeen >= std::chrono::seconds(16))
                return buildError(fields, "102");
            warehouse = found->second;
        }
        std::vector<std::string> routed = fields;
        routed[4] = target;
        const std::string marker = "bodega=" + target;
        std::string body;
        for (const auto& entry : split(fields[5], ';')) {
            if (entry == marker) continue;
            if (!body.empty()) body += ";";
            body += entry;
        }
        routed[5] = body;
        try {
            return queryWarehouse(warehouse.host, warehouse.port,
                buildSiqp(routed[1], routed[2], routed[3], routed[4], routed[5]));
        } catch (const std::exception& error) {
            std::cerr << "[INT-01] Error administrando " << target << ": " << error.what() << std::endl;
            return buildError(fields, "102");
        }
    }
    if (type == "40") return processRegistry(fields);
    if (type == "60") return distributedPurchase(fields);
    if (type == "42" || type == "44") return queryRegistered(fields);
    if (type == "12" || type == "14" || type == "16" || type == "18") {
        bool hasRegistered = false;
        {
            std::lock_guard<std::mutex> lock(registryMutex);
            hasRegistered = !warehouses.empty();
        }
        if (!hasRegistered) {
            // Mantener el comportamiento original mientras no existan registros.
            // El procesamiento antiguo se ejecuta a continuacion.
        } else {
            return queryRegistered(fields);
        }
    }


    if (type == "12") {
        // For this first version, inventory reports
        // the local catalogue only.
        return queryLocalInventory(message);
    }

    if (type == "10") {
        return queryLocalInventory(message);
    }

    if (type != "14" &&
        type != "16" &&
        type != "18") {
        return buildError(fields, "105");
    }

    std::string category =
        getAttribute(fields[5], "categoria");

    if (!validName(category)) {
        return buildError(fields, "106");
    }

    if (localCategoryExists(category)) {
        std::cout
            << "[INT-01] Categoria local: "
            << category << "\n";

        return queryLocalInventory(message);
    }

    std::cout
        << "[INT-01] Categoria no disponible localmente: "
        << category << "\n";

    // The common protocol has no equivalent for
    // STOCK_QUERY or INFO_QUERY.
    if (type != "14") {
        return buildError(fields, "105");
    }

    std::string commonRequest =
        "20/" + category;

    std::cout
        << "[INT-01] SIQP -> Mancomunado: "
        << commonRequest << "\n";

    std::string commonResponse =
        queryRemoteIsland(commonRequest);

    std::cout
        << "[INT-01] Respuesta mancomunada: "
        << commonResponse << "\n";

    std::string siqpResponse =
        translateRemoteResponse(
            commonResponse,
            fields
        );

    std::cout
        << "[INT-01] Mancomunado -> SIQP: "
        << siqpResponse << "\n";

    return siqpResponse;
}

void handleClient(VSocket *client) {
    std::unique_ptr<VSocket> socket(client);

    try {
        char buffer[BUFFER_SIZE] = {0};

        size_t bytesRead = socket->Read(
            buffer,
            BUFFER_SIZE - 1
        );

        if (bytesRead == 0 || bytesRead >= BUFFER_SIZE) {
            socket->Close();
            return;
        }

        std::string message(buffer, bytesRead);

        std::cout
            << "\n[INT-01] Solicitud: "
            << (message.find(";token=") != std::string::npos ? message.substr(0,message.find(";token="))+";token=[REDACTED]" : message) << "\n";

        std::vector<std::string> logFields = split(message, '|');
        const bool heartbeat = logFields.size() == 6 && logFields[1] == "40";
        std::string loggedRequest = message;
        if (logFields.size() == 6 &&
            (logFields[1] == "50" || logFields[1] == "52" || logFields[1] == "54")) {
            const std::string target = getAttribute(logFields[5], "bodega");
            if (validName(target)) {
                logFields[4] = target;
                loggedRequest = buildSiqp(logFields[1], logFields[2], logFields[3],
                                          logFields[4], logFields[5]);
            }
        }
        if (!heartbeat) AuditLog::write(INTERMEDIARY_ID, "SOLICITUD", loggedRequest);
        std::string response;
        if (heartbeat) {
            SSLSocket* tls = dynamic_cast<SSLSocket*>(socket.get());
            const std::string peer = tls ? tls->PeerIdentity() : "";
            if (peer.empty() || peer != logFields[3]) {
                AuditLog::write(INTERMEDIARY_ID, "REGISTRO_RECHAZADO", "Identidad TLS no autorizada");
                socket->Write(buildError(logFields,"106").c_str());
                return;
            }
        }

        try {
            response = processRequest(message);
        } catch (const std::exception &error) {
            std::cerr
                << "[INT-01] Error: "
                << error.what() << "\n";

            response = buildError(
                split(message, '|'),
                "102"
            );
        }

        std::cout
            << "[INT-01] Respuesta: "
            << response << "\n";
        if (!heartbeat) AuditLog::write(INTERMEDIARY_ID, "RESPUESTA", response);

        socket->Write(response.c_str());
        socket->Close();

    } catch (const std::exception &error) {
        std::cerr
            << "[INT-01] Error de cliente: "
            << error.what() << "\n";
        AuditLog::write(INTERMEDIARY_ID, "ERROR_CLIENTE", error.what());

        try {
            socket->Close();
        } catch (...) {
        }
    }
}

int main() {
    try {
        std::unique_ptr<VSocket> server(
            new SSLSocket(
                "certs/server.crt",
                "certs/server.key",
                false
            )
        );

        server->Bind(CLIENT_PORT);
        server->MarkPassive(5);

        std::cout
            << "====================================\n"
            << " INTERMEDIARIO SIQP/1.0 - INT-01\n"
            << "====================================\n"
            << "Clientes TLS: " << CLIENT_PORT << "\n"
            << "Inventario local: "
            << INVENTORY_IP << ":"
            << INVENTORY_PORT << "\n"
            << "Servidor mancomunado remoto: "
            << REMOTE_IP << ":"
            << REMOTE_PORT << "\n"
            << std::endl;

        std::thread(dashboardServer).detach();

        std::thread([]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                std::vector<std::string> disconnected;
                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    const auto now = std::chrono::steady_clock::now();
                    for (const auto& item : warehouses) {
                        if (warehouseOnline[item.first] &&
                            now - item.second.lastSeen >= std::chrono::seconds(16)) {
                            warehouseOnline[item.first] = false;
                            disconnected.push_back(item.first);
                        }
                    }
                }
                for (const auto& id : disconnected)
                    AuditLog::write(INTERMEDIARY_ID, "BODEGA_DESCONECTADA", "bodega=" + id);
            }
        }).detach();

        while (true) {
            try {
                VSocket *client =
                    server->AcceptConnection();

                std::thread worker(
                    handleClient,
                    client
                );

                worker.detach();

            } catch (const std::exception &error) {
                std::cerr
                    << "[INT-01] Error aceptando conexion: "
                    << error.what() << "\n";
            }
        }

    } catch (const std::exception &error) {
        std::cerr
            << "Error iniciando intermediario: "
            << error.what() << "\n";

        return 1;
    }

    return 0;
}
