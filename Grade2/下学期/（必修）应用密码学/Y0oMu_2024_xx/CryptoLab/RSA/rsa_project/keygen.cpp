// keygen.cpp
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <gmpxx.h>
#include "utils.h"

int main() {
    mpz_class p, q, n, phi, e, d;

    // Initialize the random state
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // Generate two large prime numbers p and q
    mpz_urandomb(p.get_mpz_t(), state, 40); // adjust the bit size as needed
    mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());

    mpz_urandomb(q.get_mpz_t(), state, 40); // adjust the bit size as needed
    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());

    // Compute n = p * q
    n = p * q;

    // Compute phi = (p - 1) * (q - 1)
    phi = (p - 1) * (q - 1);

    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537; // Common choice for e

    // Compute d such that e * d ≡ 1 (mod phi)
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());

    // Save the values to files
    save_to_file("p.txt", p);
    save_to_file("q.txt", q);
    save_to_file("n.txt", n);
    save_to_file("e.txt", e);
    save_to_file("d.txt", d);

    std::cout << "Key generation complete. Files created: p.txt, q.txt, n.txt, e.txt, d.txt." << std::endl;

    // Clear the random state
    gmp_randclear(state);
    return 0;
}
