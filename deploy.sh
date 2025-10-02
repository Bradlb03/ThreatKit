#!/bin/bash
cd /home/bradlb03/ThreatKit || exit

#Remove any local changes
git reset --hard
git clean -fd

# Pull latest code
OUTPUT=$(git pull origin main)

# Check if anything was updated
if [[ $OUTPUT != *"Already up to date."* ]]; then
    echo "$(date): Changes detected, rebuilding container..."
    docker-compose down
    docker-compose up -d --build
else
    echo "$(date): No changes, skipping rebuild."
fi
