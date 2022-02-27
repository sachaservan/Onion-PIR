#include <iostream>
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <pthread.h>
#include "nfl.hpp"
#include "tools.h"
#include "seal/seal.h"
#include "external_prod.h"
#include "util.h"
#include "pir.h"
#include "pir_server.h"
#include "pir_client.h"

using namespace std;
using namespace std::chrono;
using namespace std;
using namespace seal;
using namespace seal::util;

typedef vector<Ciphertext> GSWCiphertext;

int main(){

    uint64_t number_of_items = 1<<14;
    uint64_t size_per_item = 30000; // in bytes
    uint32_t N = 4096;

    uint32_t logt = 60;
    PirParams pir_params;

    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);
    gen_params( number_of_items, size_per_item, N, logt, pir_params);

    auto context = SEALContext::Create(parms);

    cout << "Main: Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

    random_device rd;

    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            db.get()[(i * size_per_item) + j] = i+j;
            db_copy.get()[(i * size_per_item) + j] = i+j;
            // cout<<db.get()[(i * size_per_item) + j]<<endl;
        }
    }

    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    pir_server server(parms, pir_params);

    // test serialization/deserialization of parms
    string ser_parms = serialize_params(parms);
    parms = deserialize_params(ser_parms);

    // Initialize PIR client....
    pir_client client(parms, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // test serialization/deserialization of galois keys
    string ser_gal = serialize_galoiskeys(galois_keys);
    galois_keys = deserialize_galoiskeys(context, ser_gal);

    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    //uint64_t ele_index =20;
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item);
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

    // offset in FV plaintext
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query_combined(index);

    uint32_t d1 = query.size();
    uint32_t d2 = query[0].size();
    string query_ser = serialize_query(query);
    query = deserialize_query(context, d1, d2, query_ser);

    cout<<"Main: query size = "<< query.size()<< endl;

    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    SecretKey sk = client.get_decryptor();

    GSWCiphertext enc_sk=client.get_enc_sk();
    server.set_enc_sk(enc_sk);

    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply_combined(query, 0, sk);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    Plaintext rep= client.decrypt_result(reply);

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, rep, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {

        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return -1;
        }
    }

    // Output results
    cout << "Main: PIR result correct!" << endl;
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;

    // cout << "Main: Reply num ciphertexts: " << reply.size() << endl;

    return 0;
}