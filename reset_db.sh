#!/bin/bash

rm -f data/fulgurant.db
rm -f data/fulgurant.db-shm
rm -f data/fulgurant.db-wal

# Not needed anymore as we create the DB if needed at startup
# sqlx database create