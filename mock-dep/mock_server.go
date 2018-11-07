package mock_dep

import (
	"context"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/phayes/freeport"
	"os"
	"strconv"
	"time"
)

const (
	dockerImage = "ekino/wiremock"
)

var (
	port int

	ctx context.Context
	cli *client.Client

	containerID string
)

func init() {
	var err error
	port, err = freeport.GetFreePort()
	if err != nil {
		panic(err.Error())
	}

	ctx = context.Background()

	cli, err = client.NewEnvClient()
	if err != nil {
		panic(err.Error())
	}

	err = pullImage()
	if err != nil {
		panic(err.Error())
	}
}

func GetPort() int {
	return port
}

func StartMockServer() error {
	err := createContainer()
	if err != nil {
		return err
	}

	err = startContainer()
	if err != nil {
		return err
	}

	// waiting for the server to start
	time.Sleep(3 * time.Second)

	return nil
}

func StopMockServer() error {
	timeout := 5 * time.Second
	return cli.ContainerStop(ctx, containerID, &timeout)
}

func pullImage() error {
	_, err := cli.ImagePull(ctx, dockerImage, types.ImagePullOptions{})
	return err
}

func createContainer() error {
	mockDir := os.Getenv("GOPATH") + "/src/github.com/ory/hydra/mock-dep/login"

	resp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: dockerImage,
			ExposedPorts: nat.PortSet{
				"8080/tcp": struct{}{},
			},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				"8080/tcp": []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: strconv.Itoa(port),
					},
				},
			},
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: mockDir + "/__files",
					Target: "/wiremock/__files",
				},
				{
					Type:   mount.TypeBind,
					Source: mockDir + "/mappings",
					Target: "/wiremock/mappings",
				},
			},
		},
		nil,
		"",
	)
	if err != nil {
		return err
	}

	containerID = resp.ID
	return nil
}

func startContainer() error {
	return cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
}
