import client
import client_mon

CRP = '../crypto'
PCRT = f"{CRP}/producers/usr1.crt"
PKEY = f"{CRP}/producers/usr1.key"
MCRT = f"{CRP}/monitors/usr1.crt"
MKEY = f"{CRP}/monitors/usr1.key"

print("Running client commands...")
prod = client.Producer('localhost', PCRT, PKEY)
print("\nRegistering client")
prod.register()
print("\nSigning asset")
prod.sign(asset='gkey')
print("\nVerifying asset signature")
prod.verify(asset='gkey')

print("\nRunning monitor commands...")
mon = client_mon.Monitor('localhost', MCRT, MKEY)
print("\nRegistering monitor")
mon.register()
print("\nVerifying asset signature")
mon.verify(asset='gkey')
print("\nSigning asset signature")
mon.sign(asset='sig', sigf='sig_mon')
print("\nVerifying (monitor) signature of asset signature")
mon.verify(asset='sig', sigf='sig_mon', monitor=True)
print("\nRevoking identity linked to asset signature")
mon.revoke(sigf='sig')
print("\nChecking status of identity linked to asset signature")
mon.status(sigf='sig')
