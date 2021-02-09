#include "aes.h"

void encrypt(int len, unsigned char* in, unsigned char* out, unsigned char expanded_key[176]) {
    unsigned char state[4][4];
    for (int block_start = 0; block_start < len; block_start += 16) {
        update_block_initial_state(in, state, len, block_start);

        add_round_key(state, expanded_key);

        // First 9 rounds
        for (int i = 0; i < 9; i++) {
            sub_bytes(state);
            shift_row(state);
            mix_columns(state);
            add_round_key(state, expanded_key + 16 * (i + 1));
        }

        // Last round
        sub_bytes(state);
        shift_row(state);
        add_round_key(state, expanded_key + 160);

        // Encrypted message to out
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out[block_start + i + j * 4] = state[i][j];
            }
        }
    }
}

void update_block_initial_state(unsigned char* in, unsigned char state[4][4], int len, int block_start) {
    int i, j;
    if (len - block_start >= 16) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                state[i][j] = in[block_start + j * 4 + i];
            }        
        }
    } else {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {              
                state[i][j] = block_start + j * 4 + i < len ? in[block_start + j * 4 + i] : '\0';
            }        
        }
    }
}

void sub_bytes(unsigned char state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = encrypt_sbox[state[i][j]];
        }
    }
}

void shift_row(unsigned char state[4][4]) {
    unsigned char i, temp;

    // Second row
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Third row
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Fourth row
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void mix_columns(unsigned char state[4][4]) {
    unsigned char temp[4];
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 4; i++) {
            temp[i] = state[i][j];
        }
        state[0][j] = gf_mult_2[temp[0]] ^ gf_mult_3[temp[1]] ^ temp[2] ^ temp[3];
        state[1][j] = temp[0] ^ gf_mult_2[temp[1]] ^ gf_mult_3[temp[2]] ^ temp[3];
        state[2][j] = temp[0] ^ temp[1] ^ gf_mult_2[temp[2]] ^ gf_mult_3[temp[3]];
        state[3][j] = gf_mult_3[temp[0]] ^ temp[1] ^ temp[2] ^ gf_mult_2[temp[3]];
    }
}

void add_round_key(unsigned char state[4][4], unsigned char* expanded_key) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= expanded_key[i+4*j];
        }
    }
}

void expand_key(unsigned char key[16], unsigned char expanded_key[176]) {
    for (int i = 0; i < 16; i++) {
        expanded_key[i] = key[i];
    }

    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char temp[4];

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_key[bytesGenerated + i - 4];
        }

        if (bytesGenerated % 16 == 0) {
            expand_key_core(temp, rconIteration);
            rconIteration++;
        }

        for (unsigned char i = 0; i < 4; i++) {
            expanded_key[bytesGenerated] = expanded_key[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }

}

void expand_key_core(unsigned char* in, unsigned char i) {
    // Rotate left
    unsigned int* q = (unsigned int*)in;
    *q = (*q >> 8) | ((*q & 0xff) << 24);

    // S-box
    for (int i = 0; i < 4; i++) {
        in[i] = encrypt_sbox[in[i]];
    }

    // R Con
    in[0] ^= rcon[i];
}