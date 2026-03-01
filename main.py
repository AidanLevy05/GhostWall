from scanner import *
from handler import *
from defense_runner import *

# Handler is currently beta and focused on port deception helpers.
# SCANNER --> Captures packet activity and emits classified events.
# HANDLER --> Backs up service ports, checks free ports, and is intended to pick real/fake ports for service movement.
# DEFENSE_RUNNER --> Consumes events and applies defense logic (including SSH/Cowrie routing decisions).

# main.py will route these all together
