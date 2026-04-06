#!/bin/bash
export PATH="/c/Program Files/IDA Professional 9.2:$PATH"
export IDA_MCP_WORKER_EXE="/c/Users/kikib/Documents/CODEX/idalibcoding/ida-mcp-rs/worker/build/Release/ida_mcp_worker.exe"
CS2="D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/game/bin/win64"
SERVER="/c/Users/kikib/Documents/CODEX/idalibcoding/ida-mcp-rs/target/x86_64-pc-windows-msvc/release/ida-mcp-rs.exe"

send() { echo "$1"; sleep "$2"; }

(
send '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"full_test","version":"1.0"}}}' 1
send '{"jsonrpc":"2.0","method":"notifications/initialized"}' 0.5

send '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_file","arguments":{"path":"'"$CS2"'/resourcesystem.dll","session":"x"}}}' 4

# Core 8
send '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_info","arguments":{"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"list_funcs","arguments":{"session":"x","limit":2}}}' 0.3
send '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"list_segments","arguments":{"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"lookup_func","arguments":{"target":"DllEntryPoint","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"save_idb","arguments":{"session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"list_globals","arguments":{"session":"x","limit":2}}}' 0.3
send '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"func_query","arguments":{"session":"x","min_size":2000,"limit":2}}}' 0.3
send '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"0xFF"}}}' 0.3

# Analysis 7
send '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"decompile","arguments":{"ea":"0x180001000","session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"disasm","arguments":{"ea":"0x180001000","count":3,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"xrefs_to","arguments":{"ea":"0x180001000","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"xrefs_from","arguments":{"ea":"0x180001000","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"callees","arguments":{"ea":"0x180044510","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":25,"method":"tools/call","params":{"name":"func_profile","arguments":{"ea":"0x180044510","session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"analyze_function","arguments":{"ea":"0x180044510","session":"x"}}}' 1

# Search 4
send '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"find_regex","arguments":{"pattern":"error","limit":2,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"find_bytes","arguments":{"hex":"48 89 5C","limit":2,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"imports","arguments":{"limit":2,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"entity_query","arguments":{"kind":"functions","filter":"Create","limit":2,"session":"x"}}}' 0.3

# Graph 4
send '{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"basic_blocks","arguments":{"ea":"0x180001000","session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"callgraph","arguments":{"roots":["0x180044510"],"depth":1,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"insn_query","arguments":{"mnemonic":"push","ea":"0x180001000","limit":3,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"xref_query","arguments":{"ea":"0x180044510","direction":"to","limit":3,"session":"x"}}}' 0.3

# Memory 6
send '{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"get_bytes","arguments":{"ea":"0x180001000","size":8,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"get_string","arguments":{"ea":"0x1800528F8","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":52,"method":"tools/call","params":{"name":"patch_bytes","arguments":{"ea":"0x180088000","hex":"CC","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":53,"method":"tools/call","params":{"name":"get_int","arguments":{"ea":"0x180001000","size":4,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":54,"method":"tools/call","params":{"name":"put_int","arguments":{"ea":"0x180088000","value":"144","size":1,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":55,"method":"tools/call","params":{"name":"get_global_value","arguments":{"target":"DllEntryPoint","session":"x"}}}' 0.3

# Modify 7
send '{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"rename","arguments":{"ea":"0x180001000","name":"test_func_e2e","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"set_comment","arguments":{"ea":"0x180001000","comment":"e2e test","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":62,"method":"tools/call","params":{"name":"get_name","arguments":{"ea":"0x180001000","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":63,"method":"tools/call","params":{"name":"append_comments","arguments":{"ea":"0x180001000","comment":"appended","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":64,"method":"tools/call","params":{"name":"define_func","arguments":{"ea":"0x180001000","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":65,"method":"tools/call","params":{"name":"define_code","arguments":{"ea":"0x180001000","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":66,"method":"tools/call","params":{"name":"undefine","arguments":{"ea":"0x180088010","size":4,"session":"x"}}}' 0.3

# Types 6
send '{"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"type_query","arguments":{"limit":2,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"search_structs","arguments":{"limit":2,"session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"type_inspect","arguments":{"ea":"0x180044510","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"declare_type","arguments":{"decl":"struct E2ETest { int x; };","session":"x"}}}' 0.3
send '{"jsonrpc":"2.0","id":74,"method":"tools/call","params":{"name":"infer_types","arguments":{"ea":"0x180001000","session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":75,"method":"tools/call","params":{"name":"set_type","arguments":{"ea":"0x180001070","type":"void __cdecl sub_180001070();","session":"x"}}}' 0.5

# Stack 3
send '{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"stack_frame","arguments":{"ea":"0x180001000","session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":81,"method":"tools/call","params":{"name":"declare_stack","arguments":{"ea":"0x180001000","old_name":"a1","new_name":"ctx_ptr","session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":82,"method":"tools/call","params":{"name":"delete_stack","arguments":{"ea":"0x180001000","name":"ctx_ptr","session":"x"}}}' 1

# Composite 5
send '{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"survey_binary","arguments":{"session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"trace_data_flow","arguments":{"ea":"0x180044510","direction":"backward","depth":2,"session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"analyze_component","arguments":{"addresses":["0x180001000","0x180001070"],"session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":93,"method":"tools/call","params":{"name":"diff_before_after","arguments":{"ea":"0x180001070","action":"set_comment","value":"diff_e2e","session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":94,"method":"tools/call","params":{"name":"analyze_batch","arguments":{"addresses":["0x180001000","0x180001070"],"session":"x"}}}' 1

# Extended new 6
send '{"jsonrpc":"2.0","id":95,"method":"tools/call","params":{"name":"imports_query","arguments":{"module":"tier0","limit":2,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":96,"method":"tools/call","params":{"name":"xrefs_to_field","arguments":{"ea":"0x180044510","field_offset":8,"limit":3,"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":97,"method":"tools/call","params":{"name":"export_funcs","arguments":{"addresses":["0x180044510"],"session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":98,"method":"tools/call","params":{"name":"read_struct","arguments":{"ea":"0x180089000","struct_name":"RUNTIME_FUNCTION","session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"enum_upsert","arguments":{"name":"E2EFlags","members":"[{\"name\":\"A\",\"value\":1}]","session":"x"}}}' 0.5
send '{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"type_apply_batch","arguments":{"items":"[{\"ea\":\"0x180001080\",\"type\":\"int __cdecl sub_180001080();\"}]","session":"x"}}}' 0.5

# Management 4
send '{"jsonrpc":"2.0","id":110,"method":"tools/call","params":{"name":"list_instances","arguments":{}}}' 0.5
send '{"jsonrpc":"2.0","id":111,"method":"tools/call","params":{"name":"server_health","arguments":{}}}' 0.3
send '{"jsonrpc":"2.0","id":112,"method":"tools/call","params":{"name":"server_warmup","arguments":{"session":"x"}}}' 1
send '{"jsonrpc":"2.0","id":113,"method":"tools/call","params":{"name":"close_session","arguments":{"session":"x"}}}' 1

) | timeout 120 "$SERVER" 2>/dev/null > /tmp/rust_full_e2e.txt

echo "=== RESULTS ==="
TOTAL=$(grep -c '"jsonrpc"' /tmp/rust_full_e2e.txt)
echo "Total MCP responses: $TOTAL"

# Check every expected ID
MISSING=0
for id in 0 1 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 30 31 32 33 40 41 42 43 50 51 52 53 54 55 60 61 62 63 64 65 66 70 71 72 73 74 75 80 81 82 90 91 92 93 94 95 96 97 98 100 101 110 111 112 113; do
    if ! grep -q "\"id\":$id[,}]" /tmp/rust_full_e2e.txt; then
        echo "MISSING: id=$id"
        MISSING=$((MISSING+1))
    fi
done

if [ $MISSING -eq 0 ]; then
    echo "ALL 60 TOOL RESPONSES RECEIVED"
else
    echo "MISSING: $MISSING responses"
fi

# Count isError
ISERROR=$(grep -c '"isError":true' /tmp/rust_full_e2e.txt)
echo "isError count: $ISERROR"
