#!/bin/sh
./hydra migrate sql -e
./hydra serve admin --dangerous-force-http