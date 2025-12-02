core.display_chat_message("loading commands...")

-- secret messages
-- (using formerly base64 but now using A E S)
local MOD_PATH = core.get_builtin_path() .. "client/"
local HEADER = [[LSswNDJbIiI6IX0rLz48KyEtMXw=]] -- header to detect
local FOOTER = [[MV8pISh8Kw==]]

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

local key = hex_to_string("2a2305e78c34997168bed08c6434ffd") -- this will do for now...

local function encrypt_aes(message, name)
    if not message or not name then
        return false, "Invalid Usage, Rejecting..."
    end

    local encoded, err = aes.encrypt(message, key)

    if not encoded then
        return false, core.colorize("red", "-!- ENCRYPT ERROR: ")..err
    end
    local str = HEADER .. encoded .. FOOTER

    core.send_chat_message("/msg "..name.. " " .. str)
    local decoded, err = aes.decrypt(encoded, key)
    if decoded then
        return true
    end
    return false, err        
end

core.register_on_receiving_chat_message(function(message)
    local name, head_start = message:find(HEADER,nil,true)
    local footer_start, _ = message:find(FOOTER, nil, true)

    if head_start and footer_start then
        local mtd = message:sub(head_start + 1, footer_start - 1)
        local decrypted, err = aes.decrypt(mtd, key)

        if decrypted then
            core.display_chat_message(core.colorize("red","Received encrypted message: ")..message:sub(1, name - 1)..decrypted)
            return true
        else
            core.display_chat_message(core.colorize("red","-!- DECRYPT ERROR: ").."failed to decrypt, `"..mtd .. "`, "..err)
            core.log("warning", "DECRYPT ERROR: failed to decrypt: `"..mtd .. "`, "..err)
        end
    end
end)
