// encrypt.cpp
#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include "utils.h"

void encrypt(const std::string& plaintext_file, const std::string& n_file, const std::string& e_file, const std::string& cipher_file) {
    mpz_class plaintext, n, e, ciphertext;
    std::ifstream file;

    // Read plaintext
    file.open(plaintext_file);
    std::string plaintext_hex;
    file >> plaintext_hex;
    plaintext.set_str(plaintext_hex, 16);
    file.close();

    // Read n
    file.open(n_file);
    std::string n_hex;
    file >> n_hex;
    n.set_str(n_hex, 16);
    file.close();

    // Read e
    file.open(e_file);
    std::string e_hex;
    file >> e_hex;
    e.set_str(e_hex, 16);
    file.close();

    // Encrypt: ciphertext = plaintext^e mod n
    mpz_powm(ciphertext.get_mpz_t(), plaintext.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());

    // Save ciphertext to file
    save_to_file(cipher_file, ciphertext);
    std::cout << "Encryption complete. Ciphertext saved to " << cipher_file << "." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 9) {
        std::cerr << "Usage: e3rsa -p plainfile -n nfile -e efile -c cipherfile" << std::endl;
        return 1;
    }

    std::string plainfile, nfile, efile, cipherfile;
    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (arg == "-p") {
            plainfile = argv[i + 1];
        } else if (arg == "-n") {
            nfile = argv[i + 1];
        } else if (arg == "-e") {
            efile = argv[i + 1];
        } else if (arg == "-c") {
            cipherfile = argv[i + 1];
        }
    }

    encrypt(plainfile, nfile, efile, cipherfile);
    return 0;
}
