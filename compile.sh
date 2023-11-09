#!/bin/bash

python -m grpc_tools.protoc --proto_path=./protobufs --python_out=./qdts_node/src/qdts_node/grpc_serialization --grpc_python_out=./qdts_node/src/qdts_node/grpc_serialization ./protobufs/*.proto
cp ./qdts_node/src/qdts_node/grpc_serialization/* ./client_lib/
cd qdts_node
poetry build
#cd ../qdts_orquestrator
#poetry build

