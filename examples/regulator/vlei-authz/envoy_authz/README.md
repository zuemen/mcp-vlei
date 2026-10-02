# envoy_authz — the ext_authz Check API, as agentgateway speaks it

`proto/ext_authz.proto` and `proto/shared_envoy.proto` are copied unchanged from agentgateway v1.5.0
(`crates/protos/proto/`, https://github.com/agentgateway/agentgateway, Apache License 2.0). They are
derived from Envoy's API definitions (https://github.com/envoyproxy/envoy, Apache License 2.0).

The `*_pb2.py` and `*_pb2_grpc.py` files are generated from them, unchanged, with grpcio-tools 1.73.1:

```bash
python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. \
  proto/shared_envoy.proto proto/ext_authz.proto
```

They are agentgateway's own definitions, so the messages `grpc_check.py` sends are the ones the
gateway parses.
