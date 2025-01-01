import sys
from bit import PrivateKey, network

def transferir(wif, destino):
    if destino == '':
        print('\nEndereço não informado.\nNão será feito transferência.')
        return None
    if len(destino) <= 25: 
        print (f'Carteira informada {destino} está inválida, interrompendo transação.\n------\n------\n------\nWIF: {wif}')
        return None
    try: 
        key = PrivateKey(wif)
        saldo = key.get_balance('satoshi')
        print(f'Seu saldo é: {saldo} satoshis')

        num_inputs = len(key.get_unspents())
        num_outputs = 1

        tamanho_estimado = (num_inputs*148) + (num_outputs*34) + 10

        fee_por_byte = network.get_fee(fast=True)
        fee = tamanho_estimado * fee_por_byte
        valor_a_enviar = int(saldo) - fee

        if valor_a_enviar <= 0:
            print ("Saldo Insuficiente para cobrir a taxa.")
            return 1
        else:
            try:
                transacao = key.send([(destino, valor_a_enviar, 'satoshi')], absolute_fee=True, fee=fee)
                if transacao:
                    print (f'Enviado com sucesso: {transacao}\nValor: {valor_a_enviar}')
                    return 0
            except Exception as e:
                print (f'Ocorreu um erro: {e}')
                return 1
    except:
        print (f'Ocorreu um erro: {e}')
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python send.py <WIF> <destino>")
        sys.exit(1)
    
    wif = sys.argv[1]  # Chave privada WIF
    destino = sys.argv[2]  # Endereço de destino

    transferir(wif, destino)