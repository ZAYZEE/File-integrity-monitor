#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>
// function to get the current time as a string
std::string getCurrentTime() {
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// function to compute the MD5 hash of a file
std::string getMD5Hash(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    std::ostringstream md5;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            char buffer[1024];
            while (file.read(buffer, sizeof(buffer))) {
                if (!CryptHashData(hHash, (BYTE*)buffer, sizeof(buffer), 0)) {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, 0);
                    return "";
                }
            }
            if (!CryptHashData(hHash, (BYTE*)buffer, file.gcount(), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
            BYTE hash[16];
            DWORD hashLen = sizeof(hash);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                for (int i = 0; i < sizeof(hash); i++) {
                    md5 << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return md5.str();
}

int main() {
    std::string filename = "file.txt";
    std::string previousHash = getMD5Hash(filename);
    while (true) {
        std::string currentHash = getMD5Hash(filename);
        if (currentHash != previousHash) {
            std::cout << getCurrentTime() << " - " << filename << " has changed!" << std::endl;
            previousHash = currentHash;
        }
        Sleep(5000); // wait for 5 seconds
    }
    return 0;
}
