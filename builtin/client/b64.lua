-- A self-contained Base64 encoding and decoding module for Lua.
-- This version is compatible with Lua 5.1 and 5.2, as it does not
-- use the native bitwise operators introduced in Lua 5.3.

local base64 = {}

-- The 64 characters used in Base64 encoding, plus the padding character '='
local b64_chars = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1029384756<>"
local pad_char = "="

-- Create a reverse lookup table for fast decoding
local b64_lookup = {}
for i = 1, #b64_chars do
    local char = b64_chars:sub(i, i)
    b64_lookup[char] = i - 1 -- Store as 0-63 index
end


-- ===================================================================
-- Bitwise Operation Polyfills for Lua 5.1/5.2
-- ===================================================================

-- Simulates bitwise left shift (<<)
local function bit_lshift(x, bits)
    return x * (2^bits)
end

-- Simulates bitwise right shift (>>)
local function bit_rshift(x, bits)
    return math.floor(x / (2^bits))
end

-- Simulates bitwise AND (&)
local function bit_and(a, b)
    local result = 0
    local power_of_2 = 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then
            result = result + power_of_2
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        power_of_2 = power_of_2 * 2
    end
    return result
end

-- Simulates bitwise OR (|)
local function bit_or(a, b)
    local result = 0
    local power_of_2 = 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then
            result = result + power_of_2
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        power_of_2 = power_of_2 * 2
    end
    return result
end


-- ===================================================================
-- Core Functions
-- ===================================================================

--- Encodes a string into Base64 format.
-- @param data The raw string data to encode.
-- @return The Base64 encoded string.
function base64.encode(data)
    if not data or data == "" then
        return ""
    end

    local encoded_parts = {}
    local data_len = #data

    -- Process the data in chunks of 3 bytes
    for i = 1, data_len, 3 do
        local b1 = data:byte(i)
        local b2 = data:byte(i + 1)
        local b3 = data:byte(i + 2)

        -- Combine the 3 bytes (24 bits) and extract four 6-bit chunks
        local enc1 = bit_rshift(b1, 2)
        local enc2 = bit_or(bit_lshift(bit_and(b1, 3), 4), (b2 and bit_rshift(b2, 4) or 0))
        local enc3 = b2 and bit_or(bit_lshift(bit_and(b2, 15), 2), (b3 and bit_rshift(b3, 6) or 0))
        local enc4 = b3 and bit_and(b3, 63)

        -- Convert 6-bit chunk values to Base64 characters
        local str = b64_chars:sub(enc1 + 1, enc1 + 1) ..
                    b64_chars:sub(enc2 + 1, enc2 + 1)

        if enc3 then
            str = str .. b64_chars:sub(enc3 + 1, enc3 + 1)
        else
            str = str .. pad_char
        end

        if enc4 then
            str = str .. b64_chars:sub(enc4 + 1, enc4 + 1)
        else
            str = str .. pad_char
        end

        table.insert(encoded_parts, str)
    end

    return table.concat(encoded_parts)
end

--- Decodes a Base64 string.
-- @param data The Base64 encoded string.
-- @return The decoded raw string, or nil if the input is invalid.
function base64.decode(data)
    if not data or data == "" then
        return ""
    end

    -- THE FIX IS HERE: We escape the '+' so it's treated as a literal character.
    local pattern = '[^' .. b64_chars:gsub('+', '%%+') .. '=]'
    data = data:gsub(pattern, '')
    
    -- Now this check will pass, because '+' symbols are no longer removed.
    if #data % 4 ~= 0 then
        return nil 
    end

    local decoded_parts = {}
    
    for i = 1, #data, 4 do
        local c1, c2, c3, c4 = data:sub(i, i), data:sub(i + 1, i + 1), data:sub(i + 2, i + 2), data:sub(i + 3, i + 3)
        local v1, v2 = b64_lookup[c1], b64_lookup[c2]
        
        if not v1 or not v2 then
            return nil
        end

        local b1 = bit_or(bit_lshift(v1, 2), bit_rshift(v2, 4))
        table.insert(decoded_parts, string.char(b1))

        if c3 ~= pad_char then
            local v3 = b64_lookup[c3]
            if not v3 then return nil end
            local b2 = bit_or(bit_lshift(bit_and(v2, 15), 4), bit_rshift(v3, 2))
            table.insert(decoded_parts, string.char(b2))
        end

        if c4 ~= pad_char then
            local v3 = b64_lookup[c3]
            local v4 = b64_lookup[c4]
            if not v4 then return nil end
            local b3 = bit_or(bit_lshift(bit_and(v3, 3), 6), v4)
            table.insert(decoded_parts, string.char(b3))
        end
    end

    return table.concat(decoded_parts)
end

return base64