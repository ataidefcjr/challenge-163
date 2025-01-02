import sys
from bit import PrivateKey, network

def calculate_fee(key, ballance):
    num_inputs = len(key.get_unspents())
    num_outputs = 1

    transaction_bytes = (num_inputs*148) + (num_outputs*34) + 10

    fee_per_byte = int(network.get_fee(fast=True) * 1.6)
    total_fee = int(transaction_bytes * fee_per_byte)

    satoshis_to_send = ballance - total_fee

    return fee_per_byte, satoshis_to_send


def send_all_funds(wif, address):
    if len(address) <= 25: 
        print (f'Invalid Address: {address}')
        return None
    try: 
        key = PrivateKey(wif)
        wif_address = key.address
        ballance = int(key.get_balance('satoshi'))
        print(f'Address: {wif_address} --- Balance: {ballance} satoshi')

        fee_per_byte, satoshis_to_send = calculate_fee(key,ballance)

        if satoshis_to_send <= 0:
            print (f"Insufficient funds: {ballance}")
            return
        
        print(f"Sending {satoshis_to_send} satoshis to {address} using fee {ballance - satoshis_to_send}")
        transaction = key.send([(address, satoshis_to_send, 'satoshi')], fee=fee_per_byte)

        if transaction:
            print (f'Sucessfully send, Transaction: {transaction}\n')
            return
        print (f'--------Error--------\n--Send Manually--')

    except Exception as e:
        print (f'Error: {e}')
        return

if __name__ == "__main__":
    
    wif = sys.argv[1]  # Chave privada WIF
    destino = sys.argv[2]  # Endereço de destino

    send_all_funds(wif, destino)