.PHONY: publish-dev
publish-dev:
	docker build -t gcr.io/wpe-cr-dev/jwk-check:latest .
	docker push gcr.io/wpe-cr-dev/jwk-check:latest