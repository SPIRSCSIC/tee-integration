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
print(prod.register())
print("\nSigning asset")
print(prod.sign(asset='gkey'))
print("\nVerifying asset signature")
print(prod.verify(asset='gkey'))

print("\nRunning monitor commands...")
mon = client_mon.Monitor('localhost', MCRT, MKEY)
print("\nRegistering monitor")
print(mon.register())
print("\nVerifying asset signature")
print(mon.verify(asset='gkey'))
print("\nSigning asset signature")
print(mon.sign(asset='sig', sig='sig_mon'))
print("\nVerifying (monitor) signature of asset signature")
print(mon.verify(asset='sig', sig='sig_mon', monitor=True))
print("\nRevoking identity linked to asset signature")
print(mon.revoke(sig='sig'))
print("\nChecking status of identity linked to asset signature")
print(mon.status(sig='sig'))
