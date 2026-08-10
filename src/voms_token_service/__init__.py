"""VOMS proxy minting for the UChicago ATLAS Analysis Facility MCP platform.

Mints VOMS proxies for AF users on behalf of the af-mcp-broker
(maniaclab/af-mcp-platform#112). This is the only component that mounts user
home directories: it receives an identity and the user's Globus passphrase
from the broker, runs ``voms-proxy-init`` against
``~<user>/.globus/{usercert,userkey}.pem``, and returns the proxy PEM in the
response body. The passphrase lives only in memory and is zeroed after use;
nothing is written to shared storage.
"""
