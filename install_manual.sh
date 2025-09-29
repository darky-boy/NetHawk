#!/bin/bash
# NetHawk Manual Installation Script

echo "Installing NetHawk manual pages..."

# Create man directory if it doesn't exist
sudo mkdir -p /usr/local/share/man/man1

# Copy manual page
sudo cp nethawk/man/nethawk.1 /usr/local/share/man/man1/

# Update man database
sudo mandb

echo "Manual page installed successfully!"
echo "You can now use: man nethawk"
echo "Or: nethawk --man"
