#!/usr/bin/env bash
# Wrapper that injects the IDA runtime environment for ida-hive.
export LD_LIBRARY_PATH="/home/kisrs/idapro-9.2:${LD_LIBRARY_PATH:-}"
export IDA_MCP_WORKER_EXE="/home/kisrs/下载/ida-hive/worker/build-linux/ida_mcp_worker"
export IDA_MCP_MAX_SLOTS=100
exec /home/kisrs/下载/ida-hive/target/release/ida-hive
