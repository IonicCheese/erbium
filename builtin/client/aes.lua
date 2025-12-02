--[[
AES-128-CBC Implementation with a Two-Layer API (Readable Version)

This file provides a clear, commented, and maintainable implementation of AES.

- It provides two APIs:
  1. `core`: Low-level functions that require manual IV management.
  2. `packaged`: High-level, easy-to-use functions that handle random IV
     generation and Base64 packaging automatically.
]]

-- #################################################################
-- # 0. SETUP & DEPENDENCIES                                       #
-- #################################################################

local AES_CORE = {}
local AES_PACKAGED = {}

-- Load the Base64 library, which is a dependency for the 'packaged' API.
local base64
pcall(function() base64 = dofile(core.get_builtin_path() .. "client/b64.lua") end)
if not base64 then pcall(function() base64 = dofile("b64.lua") end) end
if not base64 then error("LOADER ERROR: Could not load the required base64 library.") end

-- Seed the pseudorandom number generator with high-precision time.
if minetest and minetest.get_us_time then
    math.randomseed(minetest.get_us_time())
else
    math.randomseed(os.time())
end
-- "Burn" the first few values to improve initial randomness
math.random(); math.random(); math.random()

-- #################################################################
-- # 1. INTERNAL HELPERS & ALGORITHMS                              #
-- #################################################################

-- Bitwise XOR for Lua 5.1
local function bxor(a, b)
    local p, c = 1, 0
    while a > 0 or b > 0 do
        local ra, rb = a % 2, b % 2
        if ra ~= rb then c = c + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return c
end

-- Bitwise Left Shift for Lua 5.1
local function blshift(x, bits)
    return x * (2^bits)
end

-- String to byte-value table conversion
local function string_to_bytes(str)
    if not str then return {} end
    local bytes = {}
    for i = 1, #str do
        bytes[i] = string.byte(str, i)
    end
    return bytes
end

-- Byte-value table to string conversion
local function bytes_to_string(bytes)
    return string.char(unpack(bytes))
end

-- XOR two tables of bytes
local function xor_byte_tables(t1, t2)
    local result = {}
    for i = 1, #t1 do
        result[i] = bxor(t1[i], t2[i])
    end
    return result
end

-- AES constants
local sbox={0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
local inv_sbox={0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}
local Rcon={0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}
local Nb,Nk,Nr=4,4,10

-- Core AES transformation functions
local sub_bytes, shift_rows, inv_shift_rows, mix_columns, inv_mix_columns, add_round_key
local key_expansion, cipher, inv_cipher

do -- Scoping block for the low-level AES functions
    sub_bytes = function(state, use_inv_sbox)
        local box = use_inv_sbox and inv_sbox or sbox
        for i = 1, 16 do state[i] = box[state[i] + 1] end
    end

    shift_rows = function(state)
        local t = state[2]; state[2]=state[6]; state[6]=state[10]; state[10]=state[14]; state[14]=t
        local t1,t2=state[3],state[7]; state[3]=state[11]; state[7]=state[15]; state[11]=t1; state[15]=t2
        t = state[16]; state[16]=state[12]; state[12]=state[8]; state[8]=state[4]; state[4]=t
    end

    inv_shift_rows = function(state)
        local t = state[14]; state[14]=state[10]; state[10]=state[6]; state[6]=state[2]; state[2]=t
        local t1,t2=state[11],state[15]; state[11]=state[3]; state[15]=state[7]; state[3]=t1; state[7]=t2
        t = state[4]; state[4]=state[8]; state[8]=state[12]; state[12]=state[16]; state[16]=t
    end

    local function gmul(a, b)
        local p = 0
        for _ = 1, 8 do
            if (b % 2) == 1 then p = bxor(p, a) end
            local hi_bit_set = (a >= 0x80)
            a = blshift(a, 1) % 256
            if hi_bit_set then a = bxor(a, 0x1b) end -- XOR with irreducible polynomial
            b = math.floor(b / 2)
        end
        return p
    end

    mix_columns = function(state)
        local temp_state = {}
        for i=1,4 do
            local c = (i-1)*4
            temp_state[c+1] = bxor(bxor(gmul(state[c+1], 2), gmul(state[c+2], 3)), bxor(state[c+3], state[c+4]))
            temp_state[c+2] = bxor(bxor(state[c+1], gmul(state[c+2], 2)), bxor(gmul(state[c+3], 3), state[c+4]))
            temp_state[c+3] = bxor(bxor(state[c+1], state[c+2]), bxor(gmul(state[c+3], 2), gmul(state[c+4], 3)))
            temp_state[c+4] = bxor(bxor(gmul(state[c+1], 3), state[c+2]), bxor(state[c+3], gmul(state[c+4], 2)))
        end
        for i=1,16 do state[i] = temp_state[i] end
    end

    inv_mix_columns = function(state)
        local temp_state = {}
        for i=1,4 do
            local c = (i-1)*4
            temp_state[c+1] = bxor(bxor(gmul(state[c+1], 14), gmul(state[c+2], 11)), bxor(gmul(state[c+3], 13), gmul(state[c+4], 9)))
            temp_state[c+2] = bxor(bxor(gmul(state[c+1], 9), gmul(state[c+2], 14)), bxor(gmul(state[c+3], 11), gmul(state[c+4], 13)))
            temp_state[c+3] = bxor(bxor(gmul(state[c+1], 13), gmul(state[c+2], 9)), bxor(gmul(state[c+3], 14), gmul(state[c+4], 11)))
            temp_state[c+4] = bxor(bxor(gmul(state[c+1], 11), gmul(state[c+2], 13)), bxor(gmul(state[c+3], 9), gmul(state[c+4], 14)))
        end
        for i=1,16 do state[i] = temp_state[i] end
    end

    add_round_key = function(state, round_key)
        for i = 1, 16 do state[i] = bxor(state[i], round_key[i]) end
    end

    key_expansion = function(key)
        local w, temp_word = {}, {} -- 'w' is standard AES term for the key schedule
        for i=1,Nk do w[i]={key[4*i-3],key[4*i-2],key[4*i-1],key[4*i]} end
        for i=Nk+1,Nb*(Nr+1) do
            temp_word = {w[i-1][1], w[i-1][2], w[i-1][3], w[i-1][4]}
            if (i-1)%Nk == 0 then
                local t = temp_word[1]; temp_word[1],temp_word[2],temp_word[3],temp_word[4] = temp_word[2],temp_word[3],temp_word[4],t -- RotWord
                for j=1,4 do temp_word[j] = sbox[temp_word[j]+1] end -- SubWord
                temp_word[1] = bxor(temp_word[1], Rcon[math.floor((i-1)/Nk)]) -- XOR with Rcon
            end
            w[i] = {}
            local prev_word = w[i-Nk]
            for j=1,4 do w[i][j] = bxor(prev_word[j], temp_word[j]) end
        end
        return w
    end

    cipher = function(input_bytes, w)
        local state = {unpack(input_bytes)}; local round_key = {}
        for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[j][k] end end; add_round_key(state,round_key)
        for round=1,Nr-1 do sub_bytes(state); shift_rows(state); mix_columns(state); for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[round*Nb+j][k] end end; add_round_key(state,round_key) end
        sub_bytes(state); shift_rows(state); for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[Nr*Nb+j][k] end end; add_round_key(state,round_key)
        return state
    end

    inv_cipher = function(input_bytes, w)
        local state = {unpack(input_bytes)}; local round_key = {}
        for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[Nr*Nb+j][k] end end; add_round_key(state,round_key)
        for round=Nr-1,1,-1 do inv_shift_rows(state); sub_bytes(state,true); for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[round*Nb+j][k] end end; add_round_key(state,round_key); inv_mix_columns(state) end
        inv_shift_rows(state); sub_bytes(state,true); for j=1,4 do for k=1,4 do round_key[(j-1)*4+k]=w[j][k] end end; add_round_key(state,round_key)
        return state
    end
end

-- PKCS#7 Padding and Unpadding
local function pkcs7_pad(data_bytes)
    local block_size = 16
    local padding_len = block_size - (#data_bytes % block_size)
    if padding_len == 0 then padding_len = block_size end
    for i = 1, padding_len do table.insert(data_bytes, padding_len) end
    return data_bytes
end

local function pkcs7_unpad(data_bytes)
    if #data_bytes == 0 then return data_bytes, "Input is empty" end
    local padding_len = data_bytes[#data_bytes]
    if padding_len > #data_bytes or padding_len > 16 or padding_len < 1 then return nil, "Invalid padding length" end
    for i = #data_bytes - padding_len + 1, #data_bytes do
        if data_bytes[i] ~= padding_len then return nil, "Corrupt padding value" end
    end
    return {unpack(data_bytes, 1, #data_bytes - padding_len)}
end

-- Generates a 16-byte random IV as a raw string.
local function generate_iv_string()
    local iv_bytes = {}
    for i = 1, 16 do iv_bytes[i] = math.random(0, 255) end
    return bytes_to_string(iv_bytes)
end

-- #################################################################
-- # 2. LOW-LEVEL "CORE" API                                       #
-- #################################################################
-- This API requires you to provide the IV. It works with raw byte strings.

--- [CORE] Encrypts raw data with a given key and IV.
function AES_CORE.encrypt(plaintext, key_str, iv_str)
    if #key_str ~= 16 or #iv_str ~= 16 then return nil, "Key and IV must be 16 bytes." end
    local expanded_key = key_expansion(string_to_bytes(key_str))
    local data_bytes = pkcs7_pad(string_to_bytes(plaintext))
    local ciphertext_bytes = {}
    local prev_cipher_block = string_to_bytes(iv_str)
    for i = 1, #data_bytes, 16 do
        local block = {unpack(data_bytes, i, i + 15)}
        local block_to_encrypt = xor_byte_tables(block, prev_cipher_block)
        local encrypted_block = cipher(block_to_encrypt, expanded_key)
        for j = 1, 16 do table.insert(ciphertext_bytes, encrypted_block[j]) end
        prev_cipher_block = encrypted_block
    end
    return bytes_to_string(ciphertext_bytes)
end

--- [CORE] Decrypts raw ciphertext with a given key and IV.
function AES_CORE.decrypt(ciphertext, key_str, iv_str)
    if #key_str ~= 16 or #iv_str ~= 16 then return nil, "Key and IV must be 16 bytes." end
    if #ciphertext % 16 ~= 0 then return nil, "Ciphertext length must be a multiple of 16." end
    local expanded_key = key_expansion(string_to_bytes(key_str))
    local data_bytes = string_to_bytes(ciphertext)
    local plaintext_bytes = {}
    local prev_cipher_block = string_to_bytes(iv_str)
    for i = 1, #data_bytes, 16 do
        local block = {unpack(data_bytes, i, i + 15)}
        local decrypted_block = inv_cipher(block, expanded_key)
        local plain_block = xor_byte_tables(decrypted_block, prev_cipher_block)
        for j = 1, 16 do table.insert(plaintext_bytes, plain_block[j]) end
        prev_cipher_block = block
    end
    local unpadded_bytes, err = pkcs7_unpad(plaintext_bytes)
    if not unpadded_bytes then return nil, err end
    return bytes_to_string(unpadded_bytes)
end

-- #################################################################
-- # 3. HIGH-LEVEL "PACKAGED" API                                  #
-- #################################################################
-- This is the recommended, easy-to-use API. It handles everything.

--- [PACKAGED] Encrypts plaintext, returning a self-contained Base64 package.
function AES_PACKAGED.encrypt(plaintext, key_str)
    if type(plaintext) ~= "string" or type(key_str) ~= "string" then return nil, "Plaintext and key must be strings." end
    local iv_str = generate_iv_string()
    local raw_ciphertext, err = AES_CORE.encrypt(plaintext, key_str, iv_str)
    if not raw_ciphertext then return nil, err end
    local raw_package = iv_str .. raw_ciphertext
    return base64.encode(raw_package)
end

--- [PACKAGED] Decrypts a self-contained Base64 package.
function AES_PACKAGED.decrypt(base64_package, key_str)
    if type(base64_package) ~= "string" or type(key_str) ~= "string" then return nil, "Package and key must be strings." end
    local raw_package = base64.decode(base64_package)
    if not raw_package then return nil, "Invalid Base64." end
    if #raw_package < 16 then return nil, "Package too short." end
    local iv_str = raw_package:sub(1, 16)
    local ciphertext = raw_package:sub(17)
    return AES_CORE.decrypt(ciphertext, key_str, iv_str)
end

-- Return both APIs so the loader can choose which one to use.
return {
    core = AES_CORE,
    packaged = AES_PACKAGED
}
