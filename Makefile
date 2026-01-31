
IMAGE ?= abtapi/abt-api
TAG ?= latest

.PHONY: build push run

build:
	docker build -f /mnt/data/Dockerfile.abt.secure -t $(IMAGE):$(TAG) /mnt/data

push:
	docker push $(IMAGE):$(TAG)

run:
	docker run --rm -p 8000:8000 --env-file /mnt/data/.env.abt $(IMAGE):$(TAG)
