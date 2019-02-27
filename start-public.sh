#!/bin/sh
./hydra migrate sql -e
./hydra serve public --dangerous-force-http