-- secret messages
-- (using formerly b64 but now using A E S)
local MOD_PATH = core.get_modpath("ttd_aes")

local aes = dofile(MOD_PATH.."aes.lua").packaged

local function hex_to_string(hex_str)
    -- Make sure the hex string has an even number of characters
    if #hex_str % 2 ~= 0 then
        hex_str = "0" .. hex_str
    end
    return (hex_str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

local key = hex_to_string("2a2305e78c34997168bed08c6434ffd")

local sanity_sucess = false

-- you should hopefully never see these errors
local function sanity_check()
    local message = "TTD.AES.SANITY_CHECK: Message for AES sanity check, !(%)#@)%^}|{/,.}°*~`|><,+™."
    local encoded, err = aes.encrypt(message, key)
    local encoded2, err = aes.encrypt(message, key)

    if not encoded or not encoded2 then
        return false, core.colorize("red", "[-!-] CSM.TTD.AES: SANITY.CHECK: ENCRYPT.ERROR: ") .."Failed to encrypt, "..err
    end

    local decoded, err = aes.decrypt(encoded, key)

    if not decoded then
        return false, core.colorize("red", "[-!-] CSM.TTD.AES: SANITY.CHECK: DECRYPT.ERROR: ") .."Failed to decrypt, "..err
    end

    if encoded == encoded2 then
        sanity_sucess = true
        return false, core.colorize("orange", "[-!-] CSM.TTD.AES: SANITY.CHECK: SECURITY.WARNING: ") .."Failed to generate second IV, TTD.AES will still run but wont be as secure"
    end
    
    if decoded == message then
        sanity_sucess = true
        return true, core.colorize("lime", "[-!-] CSM.TTD.AES: SANITY.CHECK: ") .. "Sanity Check complete, TTD.AES is functioning correctly"
    end
end

core.register_chatcommand("b", {})
core.register_chatcommand("fb", {})

core.after(0.5, function()
    local success, result = sanity_check()
    core.display_chat_message(result)

    if not success then
        core.log("error", result)
    end

    dofile(MOD_PATH .. "definition.lua")
end)