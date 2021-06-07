

# This script takes in a csv with rows of the format "LABEL,IP", sets up a bridge at that
# IP, and outputs a CSV with rows of the format "LABEL,IP,BRIDGELINE"

xargs -I % ssh % "sudo bash -s" <(./setup_server.sh %)
