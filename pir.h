//
// Created by Haris Mughees on 4/21/21.
//

#include "external_prod.h"

#ifndef EXTERNAL_PROD_PIR_H
#define EXTERNAL_PROD_PIR_H

typedef vector<GSWCiphertext> PirQuery;
#define FIRST_DIM 256
#define DIM 4

struct PirParams {
    std::uint64_t n;                 // number of plaintexts in database
    std::uint32_t d;                 // number of dimensions for the database (1 or 2)
    std::uint32_t expansion_ratio;   // ratio of ciphertext to plaintext
    std::uint32_t dbc;               // decomposition bit count (used by relinearization)
    std::vector<std::uint64_t> nvec;// size of each of the d dimensions
    std::uint64_t gsw_base;
    std::uint64_t plain_base;
    std::uint64_t secret_base;
    std::uint64_t gsw_decomp_size;

};

// returns the number of coefficients needed to store one element
std::uint64_t coefficients_per_element(std::uint32_t logtp, std::uint64_t ele_size);


uint64_t elements_per_ptxt(uint32_t logt, uint64_t N, uint64_t ele_size);
vector<uint64_t> get_dimensions(uint64_t &plaintext_num, uint32_t d);
uint64_t plaintexts_per_db(uint32_t logtp, uint64_t N, uint64_t ele_num, uint64_t ele_size);
// Takes a vector of coefficients and returns the corresponding FV plaintext
void vector_to_plaintext(const std::vector<std::uint64_t> &coeffs, seal::Plaintext &plain);

// returns the number of plaintexts that the database can hold
std::uint64_t plaintexts_per_db(std::uint64_t logtp, std::uint64_t N, std::uint64_t ele_num,
                                std::uint64_t ele_size);

void gen_params(uint64_t ele_num, uint64_t ele_size, uint32_t N, uint64_t logt,
        PirParams &pir_param);

// Converts an array of bytes to a vector of coefficients, each of which is less
// than the plaintext modulus
std::vector<std::uint64_t> bytes_to_coeffs(std::uint64_t limit, const std::uint8_t *bytes,
                                           std::uint64_t size);

void coeffs_to_bytes(uint32_t limit, const Plaintext &coeffs, uint8_t *output, uint32_t size_out);


// Since the database has d dimensions, and an item is a particular cell
// in the d-dimensional hypercube, this function computes the corresponding
// index for each of the d dimensions
std::vector<std::uint64_t> compute_indices(std::uint64_t desiredIndex,
                                           std::vector<std::uint64_t> nvec);

//permutation related functions

void eval_encrypted_waksman_network(vector<Ciphertext>::iterator input,
        vector<GSWCiphertext>::iterator swapbits, int length,
        shared_ptr<SEALContext> context, int l,const int base_bit, Evaluator &eval);

void mux_inplace(Ciphertext &sample_c0, Ciphertext &sample_c1, GSWCiphertext choice_bit, shared_ptr<SEALContext> context,
            const int l, const int base_bit, Evaluator &eval);

// serialization 
string serialize_enc_sk(GSWCiphertext c);
string serialize_query(vector<GSWCiphertext> c);
string serialize_galoiskeys(GaloisKeys g);
string serialize_params(EncryptionParameters parms);

GSWCiphertext deserialize_enc_sk(shared_ptr<SEALContext> context, uint32_t len, string s);
PirQuery deserialize_query(shared_ptr<SEALContext> context, uint32_t len_d1, uint32_t len_d2, string s);
GaloisKeys deserialize_galoiskeys(shared_ptr<SEALContext> context, string s);
EncryptionParameters deserialize_params(string s);

#endif //EXTERNAL_PROD_PIR_H