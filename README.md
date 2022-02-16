# jq
```bash
jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .. | .providers? // empty'
```