#!/bin/sh
./hydra migrate sql -e
./hydra serve all --dangerous-force-http