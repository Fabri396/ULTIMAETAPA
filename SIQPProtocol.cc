
#include "SIQPProtocol.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

std::vector<std::string> splitUnescaped(
    const std::string& value,
    char separator
) {
    std::vector<std::string> result;
    std::string current;
    bool escaped = false;

    for (char character : value) {
        if (character == separator && !escaped) {
            result.push_back(current);
            current.clear();
        } else {
            current += character;
        }

        if (character == '\\' && !escaped) {
            escaped = true;
        } else {
            escaped = false;
        }
    }

    if (escaped) {
        throw std::invalid_argument("Escape incompleto");
    }

    result.push_back(current);
    return result;
}

std::string createError(
    int type,
    const std::string& messageId,
    const std::string& serverId,
    const std::string& destination
) {
    std::ostringstream stream;

    stream << "SIQP/1.0|"
           << type << "|"
           << messageId << "|"
           << serverId << "|"
           << destination << "|";

    return stream.str();
}

}

std::string SIQPProtocol::normalize(
    const std::string& value
) {
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

std::string SIQPProtocol::escapeValue(
    const std::string& value
) {
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

std::string SIQPProtocol::unescapeValue(
    const std::string& value
) {
    std::string result;

    for (size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '\\') {
            ++index;

            if (index >= value.size()) {
                throw std::invalid_argument(
                    "Escape incompleto"
                );
            }

            char character = value[index];

            if (character != '|' &&
                character != ';' &&
                character != '=' &&
                character != ',' &&
                character != '\\') {
                throw std::invalid_argument(
                    "Escape invalido"
                );
            }
        }

        result += value[index];
    }

    return result;
}

SIQPMessage SIQPProtocol::parseMessage(
    const std::string& rawMessage
) {
    std::string input = rawMessage;

    if (!input.empty() && input.back() == '\n') {
        input.pop_back();
    }

    if (!input.empty() && input.back() == '\r') {
        input.pop_back();
    }

    std::vector<std::string> fields =
        splitUnescaped(input, '|');

    if (fields.size() != 6) {
        throw std::invalid_argument(
            "El mensaje debe tener seis campos"
        );
    }

    for (size_t index = 0; index < 5; ++index) {
        if (fields[index].empty()) {
            throw std::invalid_argument(
                "Campo obligatorio vacio"
            );
        }
    }

    if (fields[1].find_first_not_of("0123456789")
        != std::string::npos) {
        throw std::invalid_argument(
            "Tipo de mensaje invalido"
        );
    }

    SIQPMessage message;

    message.version = fields[0];
    message.type = std::stoi(fields[1]);
    message.messageId = fields[2];
    message.source = fields[3];
    message.destination = fields[4];
    message.body = fields[5];

    return message;
}

std::string SIQPProtocol::buildMessage(
    const SIQPMessage& message
) {
    std::ostringstream stream;

    stream << message.version << "|"
           << std::setfill('0')
           << std::setw(2) << message.type << "|"
           << message.messageId << "|"
           << message.source << "|"
           << message.destination << "|"
           << message.body;

    return stream.str();
}

std::map<std::string, std::string>
SIQPProtocol::parseBody(const std::string& body) {
    std::map<std::string, std::string> attributes;

    if (body.empty()) {
        return attributes;
    }

    std::vector<std::string> entries =
        splitUnescaped(body, ';');

    for (const std::string& entry : entries) {
        std::vector<std::string> fields =
            splitUnescaped(entry, '=');

        if (fields.size() != 2 ||
            fields[0].empty() ||
            attributes.count(fields[0]) != 0) {
            throw std::invalid_argument(
                "Atributo invalido"
            );
        }

        attributes[fields[0]] =
            unescapeValue(fields[1]);
    }

    return attributes;
}

std::string SIQPProtocol::join(
    const std::vector<std::string>& values
) {
    std::string result;

    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            result += ",";
        }

        result += escapeValue(values[index]);
    }

    return result;
}

std::string SIQPProtocol::processRequest(
    const std::string& rawMessage,
    FileSystem& filesystem,
    const std::string& serverId
) {
    SIQPMessage request;

    try {
        request = parseMessage(rawMessage);
    } catch (const std::exception&) {
        std::string messageId = "00000";
        std::string destination = "UNKNOWN";

        try {
            std::vector<std::string> fields =
                splitUnescaped(rawMessage, '|');

            if (fields.size() > 2 && !fields[2].empty()) {
                messageId = fields[2];
            }

            if (fields.size() > 3 && !fields[3].empty()) {
                destination = fields[3];
            }
        } catch (const std::exception&) {
            // No se pudieron recuperar los campos.
        }

        return createError(
            101, messageId, serverId, destination
        );
    }

    auto reply = [&](int type, const std::string& body) {
        SIQPMessage response;

        response.version = "SIQP/1.0";
        response.type = type;
        response.messageId = request.messageId;
        response.source = serverId;
        response.destination = request.source;
        response.body = body;

        return buildMessage(response);
    };

    if (request.version != "SIQP/1.0") {
        return reply(103, "");
    }

    if (request.destination != serverId) {
        return reply(102, "");
    }

    if (request.type != 10 &&
        request.type != 12 &&
        request.type != 14 &&
        request.type != 16 &&
        request.type != 18 &&
        request.type != 50 && request.type != 52 && request.type != 54 && request.type != 60) {
        return reply(105, "");
    }

    std::map<std::string, std::string> attributes;

    try {
        attributes = parseBody(request.body);
    } catch (const std::exception&) {
        return reply(101, "");
    }

    if (request.type == 60) {
        if (attributes.size() != 3 || !attributes.count("categoria") ||
            !attributes.count("producto") || !attributes.count("cantidad")) return reply(106, "");
        const std::string category = normalize(attributes["categoria"]);
        const std::string name = normalize(attributes["producto"]);
        const std::string amount = attributes["cantidad"];
        if (category.empty() || name.empty() || amount.empty() ||
            amount.find_first_not_of("0123456789") != std::string::npos) return reply(106, "");
        try {
            unsigned long long parsed = std::stoull(amount);
            if (parsed == 0 || parsed > UINT32_MAX) return reply(106, "");
            Product product;
            try { product = filesystem.findProduct(category, name); }
            catch (const std::exception&) {
                return reply(filesystem.findCategory(category) ? 31 : 30, "");
            }
            if (product.stock < parsed) return reply(62, "disponible=" + std::to_string(product.stock));
            const uint32_t remaining = filesystem.purchaseProduct(category, name, static_cast<uint32_t>(parsed));
            const unsigned long long total = static_cast<unsigned long long>(product.price) * parsed;
            return reply(61, "producto=" + escapeValue(name) + ";cantidad=" + amount +
                ";precio=" + std::to_string(product.price) + ";total=" + std::to_string(total) +
                ";restante=" + std::to_string(remaining));
        } catch (const std::invalid_argument&) { return reply(106, ""); }
          catch (const std::out_of_range&) { return reply(106, ""); }
          catch (const std::exception&) { return reply(109, ""); }
    }

    // Administration commands are routed to a specific warehouse.
    if (request.type == 50 || request.type == 52 || request.type == 54) {
        const bool categoryOnly = request.type == 50;
        const bool addStock = request.type == 54;
        const size_t expected = categoryOnly ? 1 : (addStock ? 3 : 6);
        if (attributes.size() != expected || !attributes.count("categoria") ||
            attributes["categoria"].empty()) return reply(106, "");
        const std::string category = normalize(attributes["categoria"]);
        if (category.size() > 12 || category.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_-") != std::string::npos)
            return reply(106, "");
        auto number = [&](const std::string& key) -> uint32_t {
            if (!attributes.count(key) || attributes[key].empty() ||
                attributes[key].find_first_not_of("0123456789") != std::string::npos)
                throw std::invalid_argument("numero invalido");
            unsigned long long value = std::stoull(attributes[key]);
            if (value > UINT32_MAX) throw std::invalid_argument("fuera de rango");
            return static_cast<uint32_t>(value);
        };
        try {
            if (categoryOnly) {
                if (filesystem.findCategory(category)) return reply(56, "detalle=categoria_existente");
                filesystem.createCategory(category);
                return reply(51, "categoria=" + escapeValue(category));
            }
            if (!attributes.count("producto") || attributes["producto"].empty()) return reply(106, "");
            const std::string name = normalize(attributes["producto"]);
            if (name.size() > 12 || name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_-") != std::string::npos)
                return reply(106, "");
            const uint32_t quantity = number("cantidad");
            if (!quantity) return reply(106, "");
            if (!filesystem.findCategory(category)) return reply(30, "categoria=" + escapeValue(category));
            Product product;
            if (addStock) {
                try { product = filesystem.findProduct(category, name); }
                catch (const std::runtime_error&) { return reply(31, "producto=" + escapeValue(name)); }
                if (UINT32_MAX - product.stock < quantity) return reply(106, "");
                product.stock = quantity; // createProduct adds stock, preserving other fields.
                filesystem.createProduct(category, product);
                return reply(55, "cantidad=" + std::to_string(filesystem.findProduct(category, name).stock));
            }
            if (!attributes.count("precio") || !attributes.count("ubicacion") || !attributes.count("descripcion")) return reply(106, "");
            product.name = name;
            product.stock = quantity;
            product.price = number("precio");
            product.location = attributes["ubicacion"];
            product.description = attributes["descripcion"];
            if (product.location.size() > 63 || product.description.size() > 128 ||
                product.description.find(';') != std::string::npos) return reply(106, "");
            try { filesystem.findProduct(category, name); return reply(56, "detalle=producto_existente_use_addstock"); }
            catch (const std::runtime_error& error) {
                if (std::string(error.what()).find("product not found") == std::string::npos) throw;
            }
            filesystem.createProduct(category, product);
            return reply(53, "producto=" + escapeValue(name));
        } catch (const std::invalid_argument&) { return reply(106, ""); }
          catch (const std::exception&) { return reply(109, ""); }
    }

    bool needsCategory =
        request.type == 14 ||
        request.type == 16 ||
        request.type == 18;

    bool needsProduct =
        request.type == 16 ||
        request.type == 18;

    size_t expectedAttributes =
        (needsCategory ? 1 : 0) +
        (needsProduct ? 1 : 0);

    if (attributes.size() != expectedAttributes) {
        return reply(106, "");
    }

    if (needsCategory &&
        (attributes.count("categoria") == 0 ||
         attributes["categoria"].empty())) {
        return reply(106, "");
    }

    if (needsProduct &&
        (attributes.count("producto") == 0 ||
         attributes["producto"].empty())) {
        return reply(106, "");
    }

    std::string category = needsCategory
        ? normalize(attributes["categoria"])
        : "";

    std::string product = needsProduct
        ? normalize(attributes["producto"])
        : "";

    try {
        // 10 -> 11: HELP
        if (request.type == 10) {
            return reply(
                11,
                "help=Muestra los comandos disponibles;"
                "inventory=Muestra las categorias de la tienda;"
                "have=Muestra los productos de una categoria;"
                "stock=Muestra cuantas unidades hay de un producto;"
                "info=Muestra cantidad\\, precio\\, ubicacion "
                "y descripcion de un producto"
            );
        }

        // 12 -> 13: INVENTORY
        if (request.type == 12) {
            std::vector<std::string> categories =
                filesystem.listCategories();

            return reply(
                13,
                "categorias=" + join(categories)
            );
        }

        // 30: CATEGORIA INEXISTENTE
        if (filesystem.findCategory(category) == 0) {
            return reply(
                30,
                "categoria=" + escapeValue(category)
            );
        }

        // 14 -> 15: HAVE
        if (request.type == 14) {
            std::vector<std::string> products =
                filesystem.listProducts(category);

            return reply(
                15,
                "categoria=" + escapeValue(category) +
                ";productos=" + join(products)
            );
        }

        Product found;

        try {
            found = filesystem.findProduct(
                category, product
            );
        } catch (const std::runtime_error& error) {
            std::string detail = error.what();

            if (detail.find("product not found")
                != std::string::npos) {
                return reply(
                    31,
                    "categoria=" + escapeValue(category) +
                    ";producto=" + escapeValue(product)
                );
            }

            throw;
        }

        std::string body =
            "categoria=" + escapeValue(category) +
            ";producto=" + escapeValue(product) +
            ";cantidad=" + std::to_string(found.stock);

        // 16 -> 17: STOCK
        if (request.type == 16) {
            return reply(17, body);
        }

        // 18 -> 19: INFO
        if (found.description.find(';')
            != std::string::npos) {
            return reply(109, "");
        }

        body +=
            ";precio=" + std::to_string(found.price) +
            ";ubicacion=" + escapeValue(found.location) +
            ";descripcion=" + escapeValue(found.description);

        return reply(19, body);

    } catch (const std::exception&) {
        return reply(109, "");
    }
}
