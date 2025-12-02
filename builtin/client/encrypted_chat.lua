-- secret messages
-- (using formerly base64 but now using A E S)
local MOD_PATH = core.get_builtin_path() .. "client/"

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

core.register_chatcommand("aes", {
    description = "Send an AES encrypted message",
    param = "<player> <message>",
    func = function(text)
        local player, message = text:match("^(%S+)%s(.+)$")

        if not player or not message then
            return false, "-!- Invalid usage, command usage: .aes <player> <message>"
        end
    end
})
