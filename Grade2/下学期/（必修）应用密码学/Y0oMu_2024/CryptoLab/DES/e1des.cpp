#include <openssl/des.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>

using namespace std;
using namespace std::chrono;

const int DES_BLOCK_SIZE = 8; // DES block size is 8 bytes

void hexStringToBytes(const string &hexStr, vector<unsigned char> &data) {
    data.clear();
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        unsigned char byte = stoi(hexStr.substr(i, 2), nullptr, 16);
        data.push_back(byte);
    }
}

void bytesToHexString(const vector<unsigned char> &data, string &hexStr) {
    stringstream ss;
    for (size_t i = 0; i < data.size(); ++i) {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    hexStr = ss.str();
}

void readFile(const string &filename, vector<unsigned char> &data) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error opening file: " << filename << endl;
        exit(1);
    }
    string hexStr((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    hexStringToBytes(hexStr, data);
}

void writeFile(const string &filename, const vector<unsigned char> &data) {
    string hexStr;
    bytesToHexString(data, hexStr);
    ofstream file(filename);
    if (!file) {
        cerr << "Error opening file: " << filename << endl;
        exit(1);
    }
    file << hexStr;
}

void desEncrypt(const vector<unsigned char> &plainText, const vector<unsigned char> &key, const vector<unsigned char> &iv, vector<unsigned char> &cipherText, const string &mode) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    memcpy(keyBlock, key.data(), key.size());
    DES_set_odd_parity(&keyBlock); // Set the key parity bits

    int keySetResult = DES_set_key_checked(&keyBlock, &schedule);
    if (keySetResult != 0) {
        cerr << "Key error, result: " << keySetResult << endl;
        exit(1);
    }

    vector<unsigned char> paddedPlainText = plainText;
    if (mode == "ECB" || mode == "CBC") {
        size_t paddingLength = DES_BLOCK_SIZE - (plainText.size() % DES_BLOCK_SIZE);
        paddedPlainText.insert(paddedPlainText.end(), paddingLength, static_cast<unsigned char>(paddingLength));
    }

    cipherText.resize(paddedPlainText.size());
    unsigned char ivec[DES_BLOCK_SIZE];
    memcpy(ivec, iv.data(), iv.size());

    int num = 0;

    if (mode == "ECB") {
        for (size_t i = 0; i < paddedPlainText.size(); i += DES_BLOCK_SIZE) {
            DES_ecb_encrypt((DES_cblock *)(paddedPlainText.data() + i), (DES_cblock *)(cipherText.data() + i), &schedule, DES_ENCRYPT);
        }
    } else if (mode == "CBC") {
        DES_ncbc_encrypt(paddedPlainText.data(), cipherText.data(), paddedPlainText.size(), &schedule, &ivec, DES_ENCRYPT);
    } else if (mode == "CFB") {
        DES_cfb_encrypt(paddedPlainText.data(), cipherText.data(), 8, paddedPlainText.size(), &schedule, &ivec, DES_ENCRYPT);
    } else if (mode == "OFB") {
        DES_ofb_encrypt(paddedPlainText.data(), cipherText.data(), 8, paddedPlainText.size(), &schedule, &ivec);
    }
}

void desDecrypt(const vector<unsigned char> &cipherText, const vector<unsigned char> &key, const vector<unsigned char> &iv, vector<unsigned char> &plainText, const string &mode) {
    DES_cblock keyBlock;
    DES_key_schedule schedule;

    memcpy(keyBlock, key.data(), key.size());
    DES_set_odd_parity(&keyBlock); // Set the key parity bits

    int keySetResult = DES_set_key_checked(&keyBlock, &schedule);
    if (keySetResult != 0) {
        cerr << "Key error, result: " << keySetResult << endl;
        exit(1);
    }

    plainText.resize(cipherText.size());
    unsigned char ivec[DES_BLOCK_SIZE];
    memcpy(ivec, iv.data(), iv.size());

    int num = 0;

    if (mode == "ECB") {
        for (size_t i = 0; i < cipherText.size(); i += DES_BLOCK_SIZE) {
            DES_ecb_encrypt((DES_cblock *)(cipherText.data() + i), (DES_cblock *)(plainText.data() + i), &schedule, DES_DECRYPT);
        }
    } else if (mode == "CBC") {
        DES_ncbc_encrypt(cipherText.data(), plainText.data(), cipherText.size(), &schedule, &ivec, DES_DECRYPT);
    } else if (mode == "CFB") {
        DES_cfb_encrypt(cipherText.data(), plainText.data(), 8, cipherText.size(), &schedule, &ivec, DES_DECRYPT);
    } else if (mode == "OFB") {
        DES_ofb_encrypt(cipherText.data(), plainText.data(), 8, cipherText.size(), &schedule, &ivec);
    }

    // Remove padding for ECB and CBC modes
    if (mode == "ECB" || mode == "CBC") {
        if (!plainText.empty()) {
            size_t paddingLength = plainText.back();
            if (paddingLength < DES_BLOCK_SIZE) {
                plainText.resize(plainText.size() - paddingLength);
            }
        }
    }
}

void measureSpeed(const string &mode, const vector<unsigned char> &plainText, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    vector<unsigned char> cipherText, decryptedText;
    auto start = high_resolution_clock::now();
    for (int i = 0; i < 20; ++i) {
        desEncrypt(plainText, key, iv, cipherText, mode);
    }
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();
    double speed = (5.0 * 20 / duration) * 1000; // MB/sec
    cout << "Encryption speed for " << mode << ": " << speed << " MB/sec" << endl;

    start = high_resolution_clock::now();
    for (int i = 0; i < 20; ++i) {
        desDecrypt(cipherText, key, iv, decryptedText, mode);
    }
    end = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(end - start).count();
    speed = (5.0 * 20 / duration) * 1000; // MB/sec
    cout << "Decryption speed for " << mode << ": " << speed << " MB/sec" << endl;
}

int main(int argc, char *argv[]) {
    if (argc < 11) {
        cerr << "Usage: e1des -p plainfile -k keyfile [-v vifile] -m mode -c cipherfile" << endl;
        return 1;
    }

    string plainFile, keyFile, viFile, mode, cipherFile;
    for (int i = 1; i < argc; ++i) {
        if (string(argv[i]) == "-p") {
            plainFile = argv[++i];
        } else if (string(argv[i]) == "-k") {
            keyFile = argv[++i];
        } else if (string(argv[i]) == "-v") {
            viFile = argv[++i];
        } else if (string(argv[i]) == "-m") {
            mode = argv[++i];
        } else if (string(argv[i]) == "-c") {
            cipherFile = argv[++i];
        }
    }

    vector<unsigned char> plainText, key, iv, cipherText, decryptedText;
    readFile(plainFile, plainText);
    readFile(keyFile, key);
    if (!viFile.empty()) {
        readFile(viFile, iv);
    } else {
        iv = vector<unsigned char>(DES_BLOCK_SIZE, 0); // Default IV if not provided
    }

    // Encryption and decryption
    desEncrypt(plainText, key, iv, cipherText, mode);
    writeFile(cipherFile, cipherText);
    // desDecrypt(cipherText, key, iv, decryptedText, mode);
    // writeFile("decrypted_" + plainFile, decryptedText);

    // Performance testing
    vector<unsigned char> testData(5 * 1024 * 1024, 'A'); // 5MB of data
    cout << "Performance testing..." << endl;
    measureSpeed("ECB", testData, key, iv);
    measureSpeed("CBC", testData, key, iv);
    measureSpeed("CFB", testData, key, iv);
    measureSpeed("OFB", testData, key, iv);

    return 0;
}
