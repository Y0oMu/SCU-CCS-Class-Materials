// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <fstream>
#include <gmpxx.h>

void save_to_file(const std::string& filename, const mpz_class& value) {
    std::ofstream file(filename);
    file << value.get_str(16);
    file.close();
}

#endif // UTILS_H
