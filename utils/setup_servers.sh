
# This script takes in a csv with rows of the format "LABEL,IP", sets up a bridge at that
# IP, and outputs a CSV with rows of the format "LABEL,IP,BRIDGELINE"

# This is for fresh bridges, so...
SSH='ssh -o StrictHostKeyChecking=accept-new'

# XXX: For some reason, this isn't running in parralel, so some work to do
cut -d, -f2 <$1 | xargs -I % sh -c "echo % && $SSH % 'sudo bash -s' <./setup_server.sh" >/dev/null

cat $1 | xargs -I % bash -c "echo %,\$($SSH \$(echo % | cut -d, -f2) 'sudo cat /pt/obfs/bridgeline.txt' | sed \"s/<IP ADDRESS>/\$(echo % | cut -d, -f2)/g\")"
