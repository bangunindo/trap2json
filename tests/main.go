package main

import (
	"context"
	tc "github.com/testcontainers/testcontainers-go"
	"log"
)

type ContainerInfo struct {
	Container tc.ContainerRequest
	Resource  tc.Container
}

func setup(ctx context.Context, container *ContainerInfo) {
	ctr, err := tc.GenericContainer(
		ctx,
		tc.GenericContainerRequest{
			ContainerRequest: container.Container,
			Started:          true,
		},
	)
	if err != nil {
		log.Fatalf("failed creating container %s", err)
	}
	container.Resource = ctr
}

func teardown(ctx context.Context, container *ContainerInfo) {
	container.Container.Mounts = tc.ContainerMounts{}
	if err := container.Resource.Terminate(ctx); err != nil {
		log.Printf("failed terminating container %s\n", container.Container.Name)
	}
}
