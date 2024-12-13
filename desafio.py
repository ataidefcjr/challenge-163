import random
import time
import multiprocessing
import secp256k1
import hashlib
import base58


def generate_random_key():
    """Gera uma chave privada substituindo os 'x' por números hexadecimais aleatórios de forma mais eficiente."""
    key_list = list(partial_key)
    num_x = key_list.count('x')

    random_hex = random.choices(hex_chars, k=num_x)
    
    # Substituindo 'x' por caracteres hexadecimais gerados
    j = 0
    for i in range(len(key_list)):
        if key_list[i] == 'x':
            key_list[i] = random_hex[j]
            j += 1
    
    return "".join(key_list)



def check_key(private_key_hex):
    """Verifica se a chave privada corresponde ao endereço de destino."""
    try: 
        priv_key = bytes.fromhex(private_key_hex)
        private_key = secp256k1.PrivateKey(priv_key)
        public_key = private_key.pubkey
        
        pub_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key.serialize()).digest()).digest()
        network_prefix = b'\x00' + pub_key_hash
        checksum = hashlib.sha256(hashlib.sha256(network_prefix).digest()).digest()[:4]
        address_bytes = network_prefix + checksum
        address = base58.b58encode(address_bytes).decode('utf-8')
        return address == target_address
    except Exception as e:
        print(f"Erro na verificação: {e}")
        return False


def brute_force_worker(queue, stop_event):
    """Executa o brute-force em uma thread para tentar encontrar a chave privada."""
    hashes_checked = 0
    while not stop_event.is_set():
        private_key = generate_random_key()
        if check_key(private_key):
            print(f"\nChave privada encontrada: {private_key}\n")
            with open('key.txt', "w") as file:
                file.write(f"Chave privada encontrada: {private_key}")
            stop_event.set()
            break  # Sai do loop quando a chave for encontrada
        
        hashes_checked += 1

        if hashes_checked > 1000:
            queue.put(hashes_checked)
            hashes_checked = 0


def start_bruteforce_processes(partial_key, refresh_time, num_processes):
    """Inicia as threads de brute-force para trabalhar em paralelo."""
    processes = []
    queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    total_hashes = 0
    computed_hashes = 0
    last_report_time = time.time()
    
    for i in range(num_processes):
        process = multiprocessing.Process(target=brute_force_worker, args=(queue, stop_event))
        processes.append(process)
        process.start()
    try:
        while True:
            hashes_checked = queue.get()
            total_hashes += hashes_checked

            current_time = time.time()
            if current_time - last_report_time >= refresh_time:

                speed = (total_hashes - computed_hashes) / refresh_time
                print(f"Velocidade: {speed:.2f} hashes/s, Total de hashes verificadas: {total_hashes}", end='\r')
                computed_hashes = total_hashes
                last_report_time = current_time

    except KeyboardInterrupt:
        print("\nProcesso Interrompido pelo Usuário")
        print(f"Total de hashes testadas:       {total_hashes}")
        stop_event.set()
    
    for process in processes:
        process.join()


def get_valid_input(prompt, default_value, is_int=True):
    """Obtém a entrada do usuário e verifica se é válida."""
    user_input = input(prompt).strip()  # Remove espaços em branco antes e depois da entrada
    if not user_input:  # Se a entrada for vazia
        return default_value
    try:
        # Tenta converter para int ou float, dependendo do tipo esperado
        return int(user_input) if is_int else float(user_input)
    except ValueError:
        # Se a conversão falhar, retorna o valor padrão
        print(f"Entrada inválida. Usando o valor padrão: {default_value}")
        return default_value

if __name__ == "__main__":
    
    target_address = "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC"
    partial_key = "403b3x4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x"    
                ####0#b#
    hex_chars = "0123456789abcdef"

    # #Teste
    # target_address = "13DiRx5F1b1J8QWKATyLJZSAepKw1PkRbF"
    # partial_key = "3991xb084d812356x128xa06a4192587b7xa984fd08dbx31af8e9d4e70810ab2"
    # print ("\nThe result must be: 3991db084d812356c128ba06a4192587b75a984fd08dbe31af8e9d4e70810ab2\n")


    refresh_time = get_valid_input('Taxa de atualização (em segundos): ', 1, is_int=True)  # Valor padrão 1 segundo
    num_processes = get_valid_input("Quantidade de Threads (Padrão 12): ", 12, is_int=True)  # Valor padrão 12 threads
    start_bruteforce_processes(partial_key, refresh_time, num_processes)
