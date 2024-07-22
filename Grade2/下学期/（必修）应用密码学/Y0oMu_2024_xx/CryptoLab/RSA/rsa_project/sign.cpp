// sign.cpp
#include <iostream>
#include <fstream>
#include <gmpxx.h>
#include "utils.h"

void sign(const std::string& plaintext_file, const std::string& n_file, const std::string& d_file, const std::string& signature_file) {
    mpz_class plaintext, n, d, signature;
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

    // Read d
    file.open(d_file);
    std::string d_hex;
    file >> d_hex;
    d.set_str(d_hex, 16);
    file.close();

    // Sign: signature = plaintext^d mod n
    mpz_powm(signature.get_mpz_t(), plaintext.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

    // Save signature to file
    save_to_file(signature_file, signature);
    std::cout << "Signing complete. Signature saved to " << signature_file << "." << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 9) {
        std::cerr << "Usage: e3rsa -p plainfile -n nfile -d dfile -c signaturefile" << std::endl;
        return 1;
    }

    std::string plainfile, nfile, dfile, signaturefile;
    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (arg == "-p") {
            plainfile = argv[i + 1];
        } else if (arg == "-n") {
            nfile = argv[i + 1];
        } else if (arg == "-d") {
            dfile = argv[i + 1];
        } else if (arg == "-c") {
            signaturefile = argv[i + 1];
        }
    }

    sign(plainfile, nfile, dfile, signaturefile);
    return 0;
}
