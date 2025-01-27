import os
import random
import subprocess
import sys

# Check if the plugin.txt file exists
if not os.path.isfile("plugin.txt"):
    print("File plugin.txt not found!")
    sys.exit(1)

# Create the extracted_plugins directory if it doesn't exist
os.makedirs("extracted_plugins", exist_ok=True)

# Navigate to the extracted_plugins directory
os.chdir("extracted_plugins")

# Extract 3 random plugin names from plugin.txt
with open("../plugin.txt", "r") as file:
    plugin_names = file.readlines()
    selected_plugins = random.sample(plugin_names, 1467)

# Read each plugin name
for plugin_name in selected_plugins:
    plugin_name = plugin_name.strip()  # Remove any leading/trailing whitespace
    # Set the SVN URL for the plugin
    svn_url = f"https://plugins.svn.wordpress.org/{plugin_name}/trunk/"
    
    # Create a directory for the plugin if it doesn't exist
    os.makedirs(plugin_name, exist_ok=True)

    # Navigate to the plugin directory
    os.chdir(plugin_name)

    # Checkout the latest version from the SVN repository
    try:
        result = subprocess.run(["svn", "checkout", svn_url, "."], check=True, capture_output=True)
        print(f"Downloaded the latest version of {plugin_name} to {os.getcwd()}")
    except subprocess.CalledProcessError as e:
        # Handle the error (e.g., 404 not found)
        print(f"Error downloading {plugin_name}: {e.stderr.decode().strip()}")
    
    # Navigate back to the extracted_plugins directory
    os.chdir("..")
