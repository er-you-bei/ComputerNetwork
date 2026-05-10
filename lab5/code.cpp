#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

struct LicenseRecord {
    std::string serial;
    std::string username;
    std::string password;
    std::string typeName;
    int limit = 0;
};

struct SessionRecord {
    std::string serial;
    std::string token;
    std::string clientId;
    std::time_t lastHeartbeat = 0;
};

struct VerifyResult {
    bool granted = false;
    bool restored = false;
    std::string token;
    int limit = 0;
    std::string message;
};

std::vector<std::string> split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    std::istringstream stream(text);
    while (std::getline(stream, current, delimiter)) {
        parts.push_back(current);
    }
    return parts;
}

std::string trim(const std::string& text) {
    const std::string whitespace = " \t\r\n";
    const auto begin = text.find_first_not_of(whitespace);
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(whitespace);
    return text.substr(begin, end - begin + 1);
}

std::string randomDigits(std::size_t length) {
    static std::mt19937 rng{std::random_device{}()};
    static std::uniform_int_distribution<int> dist(0, 9);
    std::string result;
    result.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(static_cast<char>('0' + dist(rng)));
    }
    return result;
}

std::string randomToken(std::size_t length) {
    static const char alphabet[] = "0123456789abcdef";
    static std::mt19937 rng{std::random_device{}()};
    static std::uniform_int_distribution<int> dist(0, 15);
    std::string result;
    result.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(alphabet[dist(rng)]);
    }
    return result;
}

int parseLicenseLimit(const std::string& typeText) {
    std::string digits;
    for (char ch : typeText) {
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            digits.push_back(ch);
        }
    }
    if (digits.empty()) {
        return 0;
    }
    return std::stoi(digits);
}

bool sendAll(SOCKET socketHandle, const std::string& data) {
    const char* buffer = data.c_str();
    int remaining = static_cast<int>(data.size());
    while (remaining > 0) {
        int sent = send(socketHandle, buffer, remaining, 0);
        if (sent == SOCKET_ERROR) {
            return false;
        }
        buffer += sent;
        remaining -= sent;
    }
    return true;
}

std::string receiveLine(SOCKET socketHandle) {
    std::string result;
    char buffer[512];
    while (true) {
        int received = recv(socketHandle, buffer, sizeof(buffer), 0);
        if (received == 0) {
            break;
        }
        if (received == SOCKET_ERROR) {
            return "";
        }
        result.append(buffer, buffer + received);
        if (result.find('\n') != std::string::npos) {
            break;
        }
    }
    const auto newline = result.find('\n');
    if (newline != std::string::npos) {
        result.erase(newline);
    }
    return trim(result);
}

bool sendRequest(const std::string& host, unsigned short port, const std::string& request, std::string& response) {
    response.clear();

    SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        closesocket(socketHandle);
        return false;
    }

    if (connect(socketHandle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        closesocket(socketHandle);
        return false;
    }

    if (!sendAll(socketHandle, request + "\n")) {
        closesocket(socketHandle);
        return false;
    }

    shutdown(socketHandle, SD_SEND);
    response = receiveLine(socketHandle);
    closesocket(socketHandle);
    return !response.empty();
}

class LicenseServer {
public:
    explicit LicenseServer(std::string stateFile, int timeoutSeconds)
        : stateFile_(std::move(stateFile)), timeoutSeconds_(timeoutSeconds) {}

    bool loadState() {
        std::lock_guard<std::mutex> lock(mutex_);
        licenses_.clear();
        sessions_.clear();

        std::ifstream input(stateFile_);
        if (!input.is_open()) {
            return true;
        }

        std::string line;
        while (std::getline(input, line)) {
            if (line.empty()) {
                continue;
            }
            const auto fields = split(line, '|');
            if (fields.empty()) {
                continue;
            }

            if (fields[0] == "L" && fields.size() >= 6) {
                LicenseRecord record;
                record.serial = fields[1];
                record.username = fields[2];
                record.password = fields[3];
                record.typeName = fields[4];
                record.limit = std::max(0, std::stoi(fields[5]));
                licenses_[record.serial] = record;
            } else if (fields[0] == "S" && fields.size() >= 5) {
                SessionRecord session;
                session.serial = fields[1];
                session.token = fields[2];
                session.clientId = fields[3];
                session.lastHeartbeat = static_cast<std::time_t>(std::stoll(fields[4]));
                sessions_[session.token] = session;
            }
        }

        cleanupExpiredLocked(std::time(nullptr));
        return saveLocked();
    }

    bool saveState() {
        std::lock_guard<std::mutex> lock(mutex_);
        return saveLocked();
    }

    std::string purchaseLicense(const std::string& username, const std::string& password, const std::string& typeText) {
        std::lock_guard<std::mutex> lock(mutex_);

        const int limit = parseLicenseLimit(typeText);
        if (limit <= 0) {
            return "ERR license type must contain a positive seat count";
        }

        LicenseRecord record;
        record.serial = generateUniqueSerialLocked();
        record.username = username;
        record.password = password;
        record.typeName = typeText;
        record.limit = limit;
        licenses_[record.serial] = record;

        if (!saveLocked()) {
            return "ERR failed to persist license state";
        }

        return "OK serial=" + record.serial + " limit=" + std::to_string(record.limit);
    }

    VerifyResult verify(const std::string& serial, const std::string& clientId, const std::string& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredLocked(std::time(nullptr));

        VerifyResult result;
        const auto licenseIt = licenses_.find(serial);
        if (licenseIt == licenses_.end()) {
            result.message = "serial not found";
            return result;
        }

        result.limit = licenseIt->second.limit;

        if (!token.empty()) {
            const auto sessionIt = sessions_.find(token);
            if (sessionIt != sessions_.end() && sessionIt->second.serial == serial) {
                sessionIt->second.clientId = clientId;
                sessionIt->second.lastHeartbeat = std::time(nullptr);
                result.granted = true;
                result.restored = true;
                result.token = sessionIt->second.token;
                result.message = "restored existing session";
                saveLocked();
                return result;
            }
        }

        const int activeCount = activeCountForSerialLocked(serial);
        if (activeCount >= licenseIt->second.limit) {
            result.message = "license capacity reached";
            return result;
        }

        SessionRecord session;
        session.serial = serial;
        session.clientId = clientId;
        session.token = randomToken(16);
        session.lastHeartbeat = std::time(nullptr);
        sessions_[session.token] = session;

        result.granted = true;
        result.restored = false;
        result.token = session.token;
        result.message = "new session created";
        saveLocked();
        return result;
    }

    bool heartbeat(const std::string& serial, const std::string& clientId, const std::string& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredLocked(std::time(nullptr));

        const auto sessionIt = sessions_.find(token);
        if (sessionIt == sessions_.end()) {
            return false;
        }
        if (sessionIt->second.serial != serial) {
            return false;
        }
        if (!clientId.empty() && sessionIt->second.clientId != clientId) {
            sessionIt->second.clientId = clientId;
        }
        sessionIt->second.lastHeartbeat = std::time(nullptr);
        saveLocked();
        return true;
    }

    bool release(const std::string& serial, const std::string& clientId, const std::string& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredLocked(std::time(nullptr));

        const auto sessionIt = sessions_.find(token);
        if (sessionIt == sessions_.end()) {
            return false;
        }
        if (sessionIt->second.serial != serial) {
            return false;
        }
        if (!clientId.empty() && sessionIt->second.clientId != clientId) {
            return false;
        }

        sessions_.erase(sessionIt);
        saveLocked();
        return true;
    }

    std::string statusText() {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredLocked(std::time(nullptr));

        std::ostringstream out;
        out << "Server state: licenses=" << licenses_.size() << ", sessions=" << sessions_.size() << '\n';
        for (const auto& [serial, license] : licenses_) {
            out << "  serial=" << serial
                << " user=" << license.username
                << " type=" << license.typeName
                << " limit=" << license.limit
                << " active=" << activeCountForSerialLocked(serial)
                << '\n';
        }
        return out.str();
    }

    bool run(unsigned short port, std::atomic<bool>& stopFlag) {
        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            return false;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(port);

        const BOOL reuse = TRUE;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

        if (bind(listenSocket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            return false;
        }
        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            return false;
        }

        std::thread cleanupThread([this, &stopFlag]() {
            while (!stopFlag.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                cleanupExpired();
            }
        });

        std::cout << "License server listening on port " << port << "\n";
        while (!stopFlag.load()) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSocket, &readSet);
            timeval timeout{};
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR) {
                break;
            }
            if (ready == 0) {
                continue;
            }

            sockaddr_in clientAddress{};
            int clientLength = sizeof(clientAddress);
            SOCKET clientSocket = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientLength);
            if (clientSocket == INVALID_SOCKET) {
                continue;
            }

            std::thread(&LicenseServer::handleClient, this, clientSocket).detach();
        }

        closesocket(listenSocket);
        stopFlag.store(true);
        if (cleanupThread.joinable()) {
            cleanupThread.join();
        }
        saveState();
        return true;
    }

private:
    std::string stateFile_;
    int timeoutSeconds_ = 90;
    std::mutex mutex_;
    std::unordered_map<std::string, LicenseRecord> licenses_;
    std::unordered_map<std::string, SessionRecord> sessions_;

    int activeCountForSerialLocked(const std::string& serial) const {
        int count = 0;
        for (const auto& [token, session] : sessions_) {
            (void)token;
            if (session.serial == serial) {
                ++count;
            }
        }
        return count;
    }

    std::string generateUniqueSerialLocked() {
        std::string serial;
        do {
            serial = randomDigits(10);
        } while (licenses_.find(serial) != licenses_.end());
        return serial;
    }

    void cleanupExpiredLocked(std::time_t now) {
        std::vector<std::string> toErase;
        for (const auto& [token, session] : sessions_) {
            if (now - session.lastHeartbeat > timeoutSeconds_) {
                toErase.push_back(token);
            }
        }

        for (const auto& token : toErase) {
            sessions_.erase(token);
        }
    }

    void cleanupExpired() {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::size_t before = sessions_.size();
        cleanupExpiredLocked(std::time(nullptr));
        if (sessions_.size() != before) {
            saveLocked();
        }
    }

    bool saveLocked() {
        const std::string tempFile = stateFile_ + ".tmp";
        std::ofstream output(tempFile, std::ios::trunc);
        if (!output.is_open()) {
            return false;
        }

        for (const auto& [serial, license] : licenses_) {
            output << "L|" << license.serial << '|'
                   << license.username << '|'
                   << license.password << '|'
                   << license.typeName << '|'
                   << license.limit << '\n';
        }
        for (const auto& [token, session] : sessions_) {
            output << "S|" << session.serial << '|'
                   << session.token << '|'
                   << session.clientId << '|'
                   << static_cast<long long>(session.lastHeartbeat) << '\n';
        }
        output.close();

        if (!MoveFileExA(tempFile.c_str(), stateFile_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileA(stateFile_.c_str());
            if (!MoveFileExA(tempFile.c_str(), stateFile_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                return false;
            }
        }
        return true;
    }

    std::string processRequest(const std::string& request) {
        std::istringstream stream(request);
        std::string command;
        stream >> command;

        if (command == "VERIFY") {
            std::string serial;
            std::string clientId;
            std::string token;
            stream >> serial >> clientId >> token;
            const VerifyResult result = verify(serial, clientId, token);
            if (!result.granted) {
                return "DENY " + result.message;
            }
            if (result.restored) {
                return "OK RESTORE " + result.token + " " + std::to_string(result.limit);
            }
            return "OK VERIFY " + result.token + " " + std::to_string(result.limit);
        }

        if (command == "HEARTBEAT") {
            std::string serial;
            std::string clientId;
            std::string token;
            stream >> serial >> clientId >> token;
            return heartbeat(serial, clientId, token) ? "OK HEARTBEAT" : "DENY heartbeat rejected";
        }

        if (command == "RELEASE") {
            std::string serial;
            std::string clientId;
            std::string token;
            stream >> serial >> clientId >> token;
            return release(serial, clientId, token) ? "OK RELEASE" : "DENY release rejected";
        }

        return "ERR unknown command";
    }

    void handleClient(SOCKET clientSocket) {
        const std::string request = receiveLine(clientSocket);
        std::string response = "ERR empty request";
        if (!request.empty()) {
            response = processRequest(request);
        }
        sendAll(clientSocket, response + "\n");
        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);
    }
};

struct ClientProfile {
    std::string serial;
    std::string token;
    std::string clientId;
};

std::string defaultClientFile() {
    return "client_license.txt";
}

std::string generateClientId() {
    return "client-" + randomToken(12);
}

bool loadClientProfile(const std::string& filePath, ClientProfile& profile) {
    std::ifstream input(filePath);
    if (!input.is_open()) {
        return false;
    }

    std::getline(input, profile.serial);
    std::getline(input, profile.token);
    std::getline(input, profile.clientId);
    profile.serial = trim(profile.serial);
    profile.token = trim(profile.token);
    profile.clientId = trim(profile.clientId);
    return !profile.serial.empty() && !profile.clientId.empty();
}

bool saveClientProfile(const std::string& filePath, const ClientProfile& profile) {
    std::ofstream output(filePath, std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }
    output << profile.serial << '\n'
           << profile.token << '\n'
           << profile.clientId << '\n';
    return true;
}

std::string askLine(const std::string& prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return trim(value);
}

void runClient(const std::string& host, unsigned short port, const std::string& profileFile, int heartbeatSeconds) {
    ClientProfile profile;
    if (!loadClientProfile(profileFile, profile)) {
        profile.serial = askLine("Enter license serial: ");
        if (profile.serial.empty()) {
            std::cout << "No serial entered. Exit.\n";
            return;
        }
        profile.token.clear();
        profile.clientId = generateClientId();
        if (!saveClientProfile(profileFile, profile)) {
            std::cout << "Unable to save client profile.\n";
            return;
        }
    }

    std::cout << "Client ID: " << profile.clientId << '\n';
    std::mutex profileMutex;

    auto tryVerify = [&](bool initial) -> bool {
        std::string currentToken;
        {
            std::lock_guard<std::mutex> lock(profileMutex);
            currentToken = profile.token;
        }

        std::string request = "VERIFY " + profile.serial + ' ' + profile.clientId;
        if (!currentToken.empty()) {
            request += ' ' + currentToken;
        }

        std::string response;
        if (!sendRequest(host, port, request, response)) {
            if (initial) {
                std::cout << "Unable to contact license server.\n";
            } else {
                std::cout << "License server unavailable, will retry.\n";
            }
            return false;
        }

        std::cout << "Server: " << response << '\n';
        const auto parts = split(response, ' ');
        if (parts.size() >= 2 && parts[0] == "OK") {
            if (parts[1] == "VERIFY" || parts[1] == "RESTORE") {
                if (parts.size() >= 3) {
                    {
                        std::lock_guard<std::mutex> lock(profileMutex);
                        profile.token = parts[2];
                    }
                    saveClientProfile(profileFile, profile);
                    return true;
                }
            }
        }
        return false;
    };

    if (!tryVerify(true)) {
        std::cout << "Authorization failed. Please try again later.\n";
        return;
    }

    std::atomic<bool> stopFlag{false};
    std::atomic<bool> authorized{true};
    std::thread heartbeatThread([&]() {
        while (!stopFlag.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(heartbeatSeconds));
            if (stopFlag.load()) {
                break;
            }

            std::string currentToken;
            {
                std::lock_guard<std::mutex> lock(profileMutex);
                currentToken = profile.token;
            }

            std::string request = authorized.load() ?
                ("HEARTBEAT " + profile.serial + ' ' + profile.clientId + ' ' + currentToken) :
                ("VERIFY " + profile.serial + ' ' + profile.clientId + ' ' + currentToken);

            std::string response;
            if (!sendRequest(host, port, request, response)) {
                authorized.store(false);
                std::cout << "Heartbeat failed, waiting for server recovery...\n";
                continue;
            }

            std::cout << "Server: " << response << '\n';
            const auto parts = split(response, ' ');
            if (parts.size() >= 2 && parts[0] == "OK") {
                if (parts[1] == "VERIFY" || parts[1] == "RESTORE") {
                    if (parts.size() >= 3) {
                        {
                            std::lock_guard<std::mutex> lock(profileMutex);
                            profile.token = parts[2];
                        }
                        saveClientProfile(profileFile, profile);
                        authorized.store(true);
                    }
                } else if (parts[1] == "HEARTBEAT") {
                    authorized.store(true);
                }
            } else {
                authorized.store(false);
                std::cout << "License authorization is not available right now.\n";
            }
        }
    });

    std::cout << "Software A is running. Press Enter to exit.\n";
    std::string exitLine;
    std::getline(std::cin, exitLine);

    stopFlag.store(true);
    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }

    std::string currentToken;
    {
        std::lock_guard<std::mutex> lock(profileMutex);
        currentToken = profile.token;
    }

    std::string releaseResponse;
    if (sendRequest(host, port, "RELEASE " + profile.serial + ' ' + profile.clientId + ' ' + currentToken, releaseResponse)) {
        std::cout << "Server: " << releaseResponse << '\n';
    }

    std::cout << "Client exited.\n";
}

void runServerConsole(LicenseServer& server, std::atomic<bool>& stopFlag) {
    std::cout << "Commands: buy <user> <password> <type>, status, quit\n";
    while (!stopFlag.load()) {
        std::cout << "> ";
        std::string line;
        if (!std::getline(std::cin, line)) {
            break;
        }
        line = trim(line);
        if (line.empty()) {
            continue;
        }

        std::istringstream stream(line);
        std::string command;
        stream >> command;

        if (command == "buy") {
            std::string username;
            std::string password;
            std::string typeText;
            stream >> username >> password >> typeText;
            if (username.empty() || password.empty() || typeText.empty()) {
                std::cout << "Usage: buy <user> <password> <type>\n";
                continue;
            }
            std::cout << server.purchaseLicense(username, password, typeText) << '\n';
        } else if (command == "status") {
            std::cout << server.statusText();
        } else if (command == "quit" || command == "exit") {
            stopFlag.store(true);
            break;
        } else {
            std::cout << "Unknown command.\n";
        }
    }
}

bool initWinsock() {
    WSADATA data{};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

void cleanupWinsock() {
    WSACleanup();
}

void printUsage() {
    std::cout << "Usage:\n"
              << "  license_auth server [port] [state_file]\n"
              << "  license_auth client [host] [port] [profile_file] [heartbeat_seconds]\n";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    if (!initWinsock()) {
        std::cout << "Failed to initialize Winsock.\n";
        return 1;
    }

    const std::string mode = argv[1];
    int exitCode = 0;

    if (mode == "server") {
        const unsigned short port = (argc >= 3) ? static_cast<unsigned short>(std::stoi(argv[2])) : 5050;
        const std::string stateFile = (argc >= 4) ? argv[3] : "license_state.db";
        std::atomic<bool> stopFlag{false};
        LicenseServer server(stateFile, 90);

        if (!server.loadState()) {
            std::cout << "Failed to load server state.\n";
            cleanupWinsock();
            return 1;
        }

        std::thread networkThread([&]() {
            if (!server.run(port, stopFlag)) {
                std::cout << "License server failed to start.\n";
                stopFlag.store(true);
            }
        });

        runServerConsole(server, stopFlag);
        stopFlag.store(true);
        if (networkThread.joinable()) {
            networkThread.join();
        }
    } else if (mode == "client") {
        const std::string host = (argc >= 3) ? argv[2] : "127.0.0.1";
        const unsigned short port = (argc >= 4) ? static_cast<unsigned short>(std::stoi(argv[3])) : 5050;
        const std::string profileFile = (argc >= 5) ? argv[4] : defaultClientFile();
        const int heartbeatSeconds = (argc >= 6) ? std::max(1, std::stoi(argv[5])) : 30;
        runClient(host, port, profileFile, heartbeatSeconds);
    } else {
        printUsage();
        exitCode = 1;
    }

    cleanupWinsock();
    return exitCode;
}
