.PHONY: publish-dev
publish-dev:
	docker build -t gcr.io/wpe-cr-dev/jwk-check:0.6 .
	docker push gcr.io/wpe-cr-dev/jwk-check:0.6