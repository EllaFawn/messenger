#!/bin/sh
# Container start: bring the database schema up to date, then run the server.
set -eu
node packages/server/dist/db/migrate-cli.js
# exec so the server receives stop signals directly and can shut down cleanly.
exec node packages/server/dist/index.js
