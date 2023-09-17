#!/bin/bash

# Update
sudo apt-get update
sudo apt-get upgrade -y


# Install dependencies
sudo apt-get install -y git

# Clone cariboulite
git clone https://github.com/cariboulabs/cariboulite.git