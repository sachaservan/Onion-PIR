//
// Created by Haris Mughees on 4/21/21.
//

#include "pir.h"

std::uint64_t coefficients_per_element(std::uint32_t logtp, std::uint64_t ele_size) {
    return ceil(8 * ele_size / (double)logtp);
}

// Number of database elements that can fit in a single FV plaintext
uint64_t elements_per_ptxt(uint32_t logt, uint64_t N, uint64_t ele_size) {
    uint64_t coeff_per_ele = coefficients_per_element(logt, ele_size);
    uint64_t ele_per_ptxt = N / coeff_per_ele;
    assert(ele_per_ptxt > 0);
    return ele_per_ptxt;
}


void coeffs_to_bytes(uint32_t limit, const Plaintext &coeffs, uint8_t *output, uint32_t size_out) {
    uint32_t room = 8;
    uint32_t j = 0;
    uint8_t *target = output;

    for (uint32_t i = 0; i < coeffs.coeff_count(); i++) {
        uint64_t src = coeffs[i];
        uint32_t rest = limit;
        while (rest && j < size_out) {
            uint32_t shift = rest;
            if (room < rest) {
                shift = room;
            }
            target[j] = target[j] << shift;
            target[j] = target[j] | (src >> (limit - shift));
            src = src << shift;
            room -= shift;
            rest -= shift;
            if (room == 0) {
                j++;
                room = 8;
            }
        }
    }
}



// Number of FV plaintexts needed to represent the database
uint64_t plaintexts_per_db(uint64_t logtp, uint64_t N, uint64_t ele_num, uint64_t ele_size) {
    uint64_t ele_per_ptxt = elements_per_ptxt(logtp, N, ele_size);
    return ceil((double)ele_num / ele_per_ptxt);
}

void gen_params(uint64_t ele_num, uint64_t ele_size, uint32_t N, uint64_t logt,
                PirParams &pir_params) {

    // Determine the maximum size of each dimension
    // plain modulus = a power of 2 plus 1
    uint64_t plain_mod = (static_cast<uint64_t>(1) << logt) + 1;
    uint64_t plaintext_num = plaintexts_per_db(logt, N, ele_num, ele_size);

#ifdef DEBUG
    cout << "log(plain mod) before expand = " << logt << endl;
    cout << "number of FV plaintexts = " << plaintext_num << endl;
#endif

    vector<uint64_t> nvec = get_dimensions(plaintext_num, 2);

    pir_params.d = nvec.size();
    pir_params.dbc = 6;
    pir_params.n = plaintext_num;
    pir_params.nvec = nvec;
    pir_params.expansion_ratio = 0; // because one ciphertext = two polys
    pir_params.gsw_base= 16;
    pir_params.plain_base= 30;
    pir_params.secret_base= 16;
    pir_params.gsw_decomp_size= 5;

}






vector<uint64_t> get_dimensions(uint64_t &plaintext_num, uint32_t d) {

    assert(d > 0);
    assert(plaintext_num > 0);

    vector<uint64_t> dimensions;
    uint64_t dim=DIM;

    uint64_t plaintext_num_copy= plaintext_num;

    uint64_t first_dim=FIRST_DIM;

    dimensions.push_back(first_dim);
    plaintext_num=first_dim;

    for (uint32_t i = plaintext_num_copy/ first_dim; i >=dim ; i= i/dim ) {

        dimensions.push_back(dim);
        plaintext_num = plaintext_num * dim;

    }

    int j=1;
    while(plaintext_num<plaintext_num_copy){
        dimensions[dimensions.size()-1]++;
        //dimensions[0]++;
        plaintext_num=1;
        for(int i=0;i<dimensions.size();i++){
            plaintext_num=plaintext_num*dimensions[i];
        }
    }



    return dimensions;
}

//bytes_to_coeffs(logt, bytes.get() + offset, process_bytes);
std::vector<std::uint64_t> bytes_to_coeffs(std::uint64_t limit, const std::uint8_t *bytes, std::uint64_t size) {


        uint64_t size_out = coefficients_per_element(limit, size);
        vector<uint64_t> output(size_out);

        uint32_t room = limit;
        uint64_t *target = &output[0];

        for (uint32_t i = 0; i < size; i++) {


            uint8_t src  = bytes[i];
            uint32_t rest = 8;
            while (rest) {
                if (room == 0) {
                    target++;
                    room = limit;
                }
                uint32_t shift = rest;
                if (room < rest) {
                    shift = room;
                }
                *target = *target << shift;
                *target = *target | (src >> (8 - shift));
                src = src << shift;
                room -= shift;
                rest -= shift;
            }
        }

        *target = *target << room;
        return output;
    }

vector<uint64_t> compute_indices(uint64_t desiredIndex, vector<uint64_t> Nvec) {
    uint32_t num = Nvec.size();
    uint64_t product = 1;

    for (uint32_t i = 0; i < num; i++) {
        product *= Nvec[i];
    }

    uint64_t j = desiredIndex;
    vector<uint64_t> result;

    for (uint32_t i = 0; i < num; i++) {

        product /= Nvec[i];
        uint64_t ji = j / product;

        result.push_back(ji);
        j -= ji * product;
    }

    return result;
}

void vector_to_plaintext(const vector<uint64_t> &coeffs, Plaintext &plain) {
    uint32_t coeff_count = coeffs.size();
    plain.resize(coeff_count);
    util::set_uint_uint(coeffs.data(), coeff_count, plain.data());
}

void
eval_encrypted_waksman_network(vector<Ciphertext>::iterator input, vector<GSWCiphertext>::iterator swapbits, int length,
                               shared_ptr<SEALContext> context, int l, const int base_bit, Evaluator &eval) {

    // We assume that swapbits fft is a triple array,
    if (length == 1)
        return;
    int ins = (int) length / 2;
    int outs = (int) length / 2;
    if (length % 2 == 0) outs--;
    int n = count_swapbits(length);


    for (int i = 0; i < ins; i++) {
        //slot/ block
        //cout<< "=======" << 2 * i << "======" << (2*i) +1 << endl;

                mux_inplace(input[2 * i ], input[((2 * i) + 1) ], swapbits[i], context,
                            l, base_bit, eval);

    }

    vector<Ciphertext> temp_up((length / 2) );
    vector<Ciphertext> temp_down(((length / 2) + (length % 2)) );

    vector<Ciphertext>::iterator temp_up_ptr = temp_up.begin();
    vector<Ciphertext>::iterator temp_down_ptr = temp_down.begin();

    for (int i = 0; i < ins; i++) {

            temp_up_ptr[i ] = input[2 * i ];
            temp_down_ptr[i ] = input[((2 * i) + 1) ];

    }

    if (length % 2 == 1) {

            temp_down_ptr[ins  ] = input[(length - 1)  ];
    }


}

void
mux_inplace(Ciphertext &sample_c0, Ciphertext &sample_c1, GSWCiphertext choice_bit, shared_ptr<SEALContext> context,
            const int l, const int base_bit, Evaluator &eval) {


        const auto &context_data = context->first_context_data();
        auto &parms = context_data->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        int N2 = parms.poly_modulus_degree();

        Plaintext pp;

        //cout<< "is_reusable= "<< is_reusable<<endl;


        Ciphertext temp_sub;
        Ciphertext temp_add;

        // temp_sub = c1 - c0
        eval.sub(sample_c1, sample_c0, temp_sub);

        // temp_add = c1 + c0
        eval.add(sample_c1, sample_c0, temp_add);


        ///external prod with choice bit
        // res_ct = b*(c1 - c0) = b* temp_sub
        Ciphertext res_ct;
        vector<uint64_t *> rlwe_decom;
        rwle_decompositions(temp_sub, context, l, base_bit, rlwe_decom);

        poc_nfllib_ntt_gsw(choice_bit, context);
        poc_nfllib_ntt_rlwe_decomp(rlwe_decom);

        res_ct.resize(context, context->first_context_data()->parms_id(), 2);
        //set_ciphertext(res_ct, context);
        poc_nfllib_external_product(choice_bit, rlwe_decom, context, l, res_ct, 1);

        poc_nfllib_intt_ct(res_ct, context);

        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();


        // c0' = c_0 + b*(c1-c0) = sample_c0 + res_ct
        eval.add_inplace(sample_c0, res_ct);

        // c1' = c0+c1-c0' = temp_add - sample_c0
        eval.sub(temp_add, sample_c0, sample_c1);
}

inline Ciphertext deserialize_ciphertext(shared_ptr<SEALContext> context, string s) {
    Ciphertext c;
    std::istringstream input(s);
    c.load(context, input);
    return c;
}

GSWCiphertext deserialize_ciphertexts(shared_ptr<SEALContext> context, uint32_t count, string s, uint32_t len_ciphertext) {
    GSWCiphertext c;
    for (uint32_t i = 0; i < count; i++) {
        c.push_back(deserialize_ciphertext(context, s.substr(i * len_ciphertext, len_ciphertext)));
    }
    return c;
}

PirQuery deserialize_query(shared_ptr<SEALContext> context, uint32_t d, uint32_t count, string s, uint32_t len_ciphertext) {
    vector<GSWCiphertext> c;
    for (uint32_t i = 0; i < d; i++) {
        c.push_back(deserialize_ciphertexts(
              context,
              count, 
              s.substr(i * count * len_ciphertext, count * len_ciphertext),
              len_ciphertext)
        );
    }
    return c;
}


inline string serialize_ciphertext(Ciphertext c) {
    std::stringstream output;
    c.save(output);
    return output.str();
}

string serialize_ciphertexts(GSWCiphertext c) {
    string s;
    for (uint32_t i = 0; i < c.size(); i++) {
        s.append(serialize_ciphertext(c[i]));
    }
    return s;
}

string serialize_query(vector<GSWCiphertext> c) {
    string s;
    for (uint32_t i = 0; i < c.size(); i++) {
      for (uint32_t j = 0; j < c[i].size(); j++) {
        s.append(serialize_ciphertext(c[i][j]));
      }
    }
    return s;
}

string serialize_params(EncryptionParameters parms) {
    std::stringstream parms_stream;
    parms.save(parms_stream);
    return parms_stream.str();
}

EncryptionParameters deserialize_params(string s) {
    std::stringstream parms_stream(s);
    EncryptionParameters parms;
    parms.load(parms_stream);
    return parms;
}


string serialize_galoiskeys(GaloisKeys g) {
    std::stringstream output;
    g.save(output);
    return output.str();
}

GaloisKeys deserialize_galoiskeys(shared_ptr<SEALContext> context, string s) {
    GaloisKeys g;
    std::stringstream parms_stream;
    g.load(*context.get(), input);
    return g;
}
