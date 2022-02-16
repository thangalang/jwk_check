#! /bin/bash

## Get the local keys
curl localhost:15000/config_dump | jq '.configs[] | select(."@type"=="type.googleapis.com/envoy.admin.v3.ListenersConfigDump") | .dynamic_listeners[] | .active_state.listener.filter_chains[] | .filters[] | .typed_config.http_filters[] | select(.name=="envoy.filters.http.jwt_authn") | .typed_config.providers '

## Get the keys for all the issuers
curl -o accounts.google.com.json https://www.googleapis.com/oauth2/v3/certs
curl -o identity-dev.wpengine.com.json https://identity-dev.wpengine.com/oauth2/default/v1/keys
curl -o identity-staging.wpengine.com.json https://identity-staging.wpengine.com/oauth2/default/v1/keys

curl -o mystaging.wpengine.com.json https://mystaging.wpengine.com/capi/private/.well-known/keys
curl -o my.dev.wpesvc.net.json https://my.dev.wpesvc.net/capi/private/.well-known/keys
curl -o my.wpengine.com.json https://my.wpengine.com/capi/private/.well-known/keys