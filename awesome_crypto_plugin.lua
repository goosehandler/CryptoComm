myproto = Proto("AwesomeCryptoProto", "Our Awesome Crypto Protocol")

local f_packet_type = ProtoField.string("myproto.type", "Packet Type")
local f_public_key = ProtoField.bytes("myproto.public_key", "Public Key", base.NONE)
local f_nonce = ProtoField.bytes("myproto.nonce", "Nonce", base.NONE)
local f_ciphertext_len = ProtoField.uint32("myproto.ciphertext_len", "Ciphertext Length", base.DEC)
local f_ciphertext = ProtoField.bytes("myproto.ciphertext", "Ciphertext", base.NONE)
local f_mac = ProtoField.bytes("myproto.mac", "HMAC", base.NONE)

myproto.fields = { f_packet_type, f_public_key, f_nonce, f_ciphertext_len, f_ciphertext, f_mac }

function is_public_key(buffer)
    local len = buffer:len()
    return len >= 90 and len <= 95 and buffer(0, 1):uint() == 0x30
end

function myproto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = myproto.name
    local subtree = tree:add(myproto, buffer(), "AwesomeCryptoProto Protocol Data")
    local offset = 0
    local buffer_len = buffer:len()

    if is_public_key(buffer) then
        subtree:add(f_packet_type, "Public Key Exchange")
        subtree:add(f_public_key, buffer(offset, buffer_len))
        return
    end

    if buffer_len < 12 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Nonce")
        return
    end

    local nonce = buffer(offset, 12)
    subtree:add(f_nonce, nonce)
    offset = offset + 12

    if buffer_len < offset + 4 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Ciphertext Length")
        return
    end

    local ciphertext_len = buffer(offset, 4):uint()
    subtree:add(f_ciphertext_len, buffer(offset, 4))
    offset = offset + 4

    if buffer_len < offset + ciphertext_len then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Ciphertext")
        return
    end

    local ciphertext = buffer(offset, ciphertext_len)
    subtree:add(f_ciphertext, ciphertext)
    offset = offset + ciphertext_len

    if buffer_len < offset + 32 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for HMAC")
        return
    end

    local mac = buffer(offset, 32)
    subtree:add(f_mac, mac)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8989, myproto)
