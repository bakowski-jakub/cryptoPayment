from stellar_sdk import Asset, Keypair, Network, Server, TransactionBuilder

# public key for receiving payments
receiver_public_key = "GCEWVURVUOUL5545BHQYQRF6BONMDAA77IKVTODVI5DNMDXSKBYITR3Z"

# sender public key
sender_public_key = "GDQOXE54DE3F45O4RRYT7V6PUFNAT36AGOTFQEW565C25LGBJTPFE622"
# sender secret key
sender_secret_key = "SCDXRHRHCZM2UH5MITXKWSETJ5XO4YNSCYQT5YEGONURQVNTMKAYOBEG"

sender_keypair = Keypair.from_secret(sender_secret_key)

print("Sender's keypair: " + str(sender_keypair) + "\n")

# check if receiver's account exists
try:
    server.load_account(receiver_public_key)
except NotFoundError:
    raise Exception("The destination account does not exist!")

# load up-to-date information on sender's account
sender_account = server.load_account(sender_public_key)

# establish connection to horizon instance on the testnet
horizon_url = "https://horizon-testnet.stellar.org"
server = Server(horizon_url)

# fetch base_fee from network
base_fee = server.fetch_base_fee()

# we are going to submit the transaction to the test network,
# so network_passphrase is `Network.TESTNET_NETWORK_PASSPHRASE`,
# if you want to submit to the public network, please use `Network.PUBLIC_NETWORK_PASSPHRASE`.
transaction = (
    TransactionBuilder(
        source_account=sender_account,
        network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        base_fee=base_fee,
    )
    .add_text_memo("Hello, Stellar!")  # Add a memo
    # Add a payment operation to the transaction
    # Send 350.1234567 XLM to receiver
    # Specify 350.1234567 lumens. Lumens are divisible to seven digits past the decimal.
    .append_payment_op(receiver_public_key, Asset.native(), "350.1234567")
    .set_timeout(30)  # Make this transaction valid for the next 30 seconds only
    .build()
)

# Sign this transaction with the secret key
# NOTE: signing is transaction is network specific. Test network transactions
# won't work in the public network. To switch networks, use the Network object
# as explained above (look for stellar_sdk.network.Network).
transaction.sign(sender_keypair)

# Let's see the XDR (encoded in base64) of the transaction we just built
print(transaction.to_xdr())

# Submit the transaction to the Horizon server.
# The Horizon server will then submit the transaction into the network for us.
response = server.submit_transaction(transaction)
print(response)

def load_last_paging_token():
    # get the last paging token from a local database/file
    return "now"

def save_paging_token(paging_token):
    # in most cases this should be saved into a local database so that it can be loaded next time new payments are streamed
    pass 

# API call to query payments involving the account
payments = server.payments().for_account(receiver_public_key)
last_token = load_last_paging_token()
if last_token:
    payments.cursor(last_token)

for payment in payments.stream():
    # record the paging token so we can start from here next time
    save_paging_token(payment["paging_token"])

    if payment["type"] != "payment":
        continue
    
    if payment['to'] != receiver_public_key:
        continue