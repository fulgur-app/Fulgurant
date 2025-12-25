#!/bin/bash

rm -f data/fulgurant.db
rm -f data/fulgurant.db-shm
rm -f data/fulgurant.db-wal

sqlx database create