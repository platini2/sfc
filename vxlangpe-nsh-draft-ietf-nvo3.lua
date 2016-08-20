--
-- VXLAN GPE and Network Service Header Dissector
-- https://tools.ietf.org/html/draft-ietf-nvo3-vxlan-gpe-02
--
-- copy this file to ~/.wireshark/plugins/
--

do
    local protocol_vxlangpe = Proto("vxlangpe", "VxLAN Generic Protocol Extension");
    local vxlangpe_flags = ProtoField.uint8("vxlangpe.flags","Flags",base.HEX)
    local vxlangpe_flag_i = ProtoField.bool("vxlangpe.flags.i","I Flag",8,
                {"Valid VNI Flag present", "Valid VNI Flag NOT present"}, 0x08)
    local vxlangpe_flag_p = ProtoField.bool("vxlangpe.flags.p","P Flag",8,
                {"Next Protocol Field Flag present", "Next Protocol Field Flag NOT present"}, 0x04)
    local vxlangpe_flag_o = ProtoField.bool("vxlangpe.flags.o","O Flag",8,
                {"OAM Flag present", "OAM Flag NOT present"}, 0x01)
    local vxlangpe_reserved1 = ProtoField.uint16("vxlangpe.reserved1","Reserved", base.HEX)
    local vxlangpe_nextprotos = {
        [1] = "IPv4",
        [2] = "IPv6",
        [3] = "Ethernet",
        [4] = "NSH",
        [5] = "MPLS"
    }
    local vxlangpe_nextproto = ProtoField.uint8("vxlangpe.nextproto","Next Protocol", base.HEX, vxlangpe_nextprotos)
    local vxlangpe_vni = ProtoField.uint24("vxlangpe.vni","VNI",base.HEX)
    local vxlangpe_reserved2 = ProtoField.uint8("vxlangpe.reserved2","Reserved", base.HEX)

    protocol_vxlangpe.fields = {vxlangpe_flags, vxlangpe_flag_i, vxlangpe_flag_p, vxlangpe_flag_o, vxlangpe_reserved1, vxlangpe_nextproto,
                             vxlangpe_vni, vxlangpe_reserved2}

    local protocol_nsh = Proto("nsh","Network Service Header");
    local nsh_flags = ProtoField.uint16("nsh.flags","Flags",base.HEX)
    local nsh_flag_version = ProtoField.uint16("nsh.flags.version","Version",
        base.DEC, nil, 0xC000)
    local nsh_flag_o = ProtoField.bool("nsh.flags.o","O Flag", 16,
        {"Valid OAM Bit present", "Valid OAM Bit NOT present"}, 0x2000)
    local nsh_flag_c = ProtoField.bool("nsh.flags.c","C Flag", 16,
        {"Valid Context Bit present", "Valid Context Bit NOT present"}, 0x1000)
    local nsh_flag_reserved = ProtoField.uint16("nsh.flags.reserved","Reserved",
        base.DEC, nil, 0x00FC0)
    local nsh_flag_length = ProtoField.uint16("nsh.flags.length","Length",
        base.DEC, nil, 0x0003F)
    local nsh_md_type = ProtoField.uint8("nsh.md_type","MD Type", base.HEX)
    local nsh_next_protos = {
        [1] = "IPv4",
        [2] = "IPv6",
        [3] = "Ethernet",
        [4] = "NSH",
        [5] = "MPLS"
    }
    local nsh_next_proto_type = ProtoField.uint8("nsh.next_proto_type",
        "Next Protocol", base.HEX, nsh_next_protos)
    local nsh_service_path_id = ProtoField.uint24("nsh.service_path_id","Service Path",
        base.HEX)
    local nsh_service_index = ProtoField.uint8("nsh.service_index","Service Index",
        base.HEX)
    local nsh_net_plt_ctx = ProtoField.uint32("nsh.net_plt_ctx",
        "NSH Context C1",base.HEX)
    local nsh_net_shd_ctx = ProtoField.uint32("nsh.net_shd_ctx",
        "NSH Context C2",base.HEX)
    local nsh_svc_plt_ctx = ProtoField.uint32("nsh.svc_plt_ctx",
        "NSH Context C3",base.HEX)
    local nsh_svc_shd_ctx = ProtoField.uint32("nsh.svc_shd_ctx",
        "NSH Context C4",base.HEX)

    protocol_nsh.fields = {nsh_flags, nsh_flag_version, nsh_flag_o, nsh_flag_c,
        nsh_flag_reserved, nsh_flag_length, nsh_md_type, nsh_next_proto_type,
        nsh_service_index, nsh_service_path_id, nsh_net_plt_ctx, nsh_net_shd_ctx,
        nsh_svc_plt_ctx, nsh_svc_shd_ctx}

    local protos = {
        [1] = Dissector.get("ip"),
        [2] = Dissector.get("ipv6"),
        [3] = Dissector.get("eth"),
        [4] = Dissector.get("eth"),                 ----------- Current Ying Patch uses NSH Protocol ID for VXLAN + ETH + NSH
        [5] = Dissector.get("mpls"),
    }

    function protocol_vxlangpe.dissector(buf, pinfo, root)
        local t = root:add(protocol_vxlangpe, buf(0,8))
        local f = t:add(vxlangpe_flags, buf(0,1))
	local vxlangpe_proto_id = buf(3,1)
        f:add(vxlangpe_flag_i, buf(0,1))
        f:add(vxlangpe_flag_p, buf(0,1))
        f:add(vxlangpe_flag_o, buf(0,1))
        t:add(vxlangpe_reserved1, buf(1,2))
        t:add(vxlangpe_nextproto, vxlangpe_proto_id)
        t:add(vxlangpe_vni, buf(4,3))
        t:add(vxlangpe_reserved2, buf(7,1))
        t:append_text(", Next Protocol: 0x" .. string.format("%x",
            buf(3, 1):uint()))
        t:append_text(", VNI: 0x" .. string.format("%x",
            buf(4, 3):uint()))
        local dissector = protos[vxlangpe_proto_id:uint()]
	if vxlangpe_proto_id:uint() == 4 then
		if buf(20,2):uint() == 35151 then                  ------- Ying Patch uses NSH Protocol ID (0x4) but encapsulation is ethernet so Check that Ethernet Header Ethertype is 0x894F (31151)
        		dissector:call(buf(8,14):tvb(), pinfo, root)
			protocol_nsh.dissector(buf(14):tvb(), pinfo, root)
		else
			dissector:call(buf(8):tvb(), pinfo, root)
		end
	else
		dissector:call(buf(8):tvb(), pinfo, root)
	end

    end

    function protocol_nsh.dissector(buf, pinfo, root)
        local nsh_t = root:add(protocol_nsh, buf(8,24))
        local nsh_f = nsh_t:add(nsh_flags, buf(8,2))
	local nsh_proto_id = buf(11,1)

        nsh_f:add(nsh_flag_version, buf(8,2))
        nsh_f:add(nsh_flag_o, buf(8,2))
        nsh_f:add(nsh_flag_c, buf(8,2))
        nsh_f:add(nsh_flag_reserved, buf(8,2))
        nsh_f:add(nsh_flag_length, buf(8,2))

        nsh_t:add(nsh_md_type, buf(10,1))
        nsh_t:add(nsh_next_proto_type, buf(11,1))
        nsh_t:add(nsh_service_path_id, buf(12,3))
        nsh_t:add(nsh_service_index, buf(15,1))

        nsh_t:add(nsh_net_plt_ctx, buf(16,4))
        nsh_t:add(nsh_net_shd_ctx, buf(20,4))
        nsh_t:add(nsh_svc_plt_ctx, buf(24,4))
        nsh_t:add(nsh_svc_shd_ctx, buf(28,4))

        nsh_t:append_text(", Version: " .. string.format("%d",
            buf(8, 1):bitfield(0,2)))
        nsh_t:append_text(", Next Protocol: 0x" .. string.format("%x",
            buf(11, 1):uint()))
        nsh_t:append_text(", Service Path ID: 0x" .. string.format("%x",
            buf(12, 3):uint()))
        nsh_t:append_text(", Service Index: 0x" .. string.format("%x",
            buf(15, 1):uint()))
        local dissector = protos[nsh_proto_id:uint()]
        dissector:call(buf(32):tvb(), pinfo, root)
    end

    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(4790, protocol_vxlangpe)
    udp_encap_table:add(6633, protocol_vxlangpe)			-------- Current SFC demo Uses Port 6633 for VXLANGPE+ETH+NSH This need to be Changed and Next Line Uncommented
--  udp_encap_table:add(6633, protocol_nsh)
end
