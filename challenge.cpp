#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <unistd.h>
#include <cmath>
#include <csignal>
#include <thread>
#include <random>
#include <secp256k1.h>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <chrono>
#include "base58.cpp"
#include <fstream>
#include <iomanip>
#include <locale>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include "base58.h"

int batch_size = 65536; //Do not change, equals to 16 ^ 4
int refresh_time;
int num_threads;
int num_processes; 
int save = 0;
int send = 0;
std::string destination;

// Global Variables
static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
std::string const hex_chars = "0123456789abcdef";
std::vector<std::string> random_prefixes;

std::string partial_key;
std::string target_address;
std::vector<unsigned char> decoded_target_address;
std::vector<int> x_positions;

volatile int found = 0; 
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER; 

std::vector<int> global_counter = {0};

// Terminal Colors
const std::string red = "\033[91m";
const std::string green = "\033[92m";
const std::string yellow = "\033[93m";
const std::string blue = "\033[94m";
const std::string cyan = "\033[96m";
const std::string reset = "\033[0m";

// Threads Args
struct ThreadArgs
{
    int thread_id;
    int refresh_time;
    int batch_size;
} ;

//Config file
struct KeyConfig {
    std::string partial_key;
    std::string target_address;
};

KeyConfig readConfigFromFile(const std::string &filename) {
    std::ifstream file(filename);
    KeyConfig config;
    
    if (file.is_open()) {
        std::getline(file, config.partial_key);
        std::getline(file, config.target_address);
        file.close();
    } else {
        throw std::runtime_error("Could not open File " + filename);
    }
    
    if (config.partial_key.empty() || config.target_address.empty()) {
        throw std::runtime_error("Incomplete config.");
    }
    
    return config;
}

// Valida os inputs
int validate_input(int value, const std::string& prompt) {
    if (value < 1 || value > 128) {
        std::cerr << "Error: " << prompt << " must be between 1 and 128 " << std::endl;
        exit(1); 
    }
    return value;
}

std::string generate_random_prefix(){
    static std::random_device rd;
    static std::mt19937 gen(rd()+14061995);

    std::stringstream ss;
    for (int i=0; i<x_positions.size() - 4; i++){
        ss << std::hex << hex_chars[gen()%16];
    }

    return ss.str();

}

// Função para gerar as chaves
std::string generate_random_key(std::vector<std::string> &output_key) {
    unsigned int sequential_counter = 0;

    std::string random_prefix;

    // Gera um prefixo único
    do {
        random_prefix = generate_random_prefix();
    } while (std::find(random_prefixes.begin(), random_prefixes.end(), random_prefix) != random_prefixes.end());
    
    // Adiciona o novo prefixo ao vetor
    random_prefixes.push_back(random_prefix);

    //Itera sobre o array de chaves
    for (int position = 0; position < output_key.size(); position ++){

        std::string new_key = partial_key;

        // Adicionar os x aleatórios
        int x_index = 0;
        for (int i = 0; i < partial_key.size(); i++){
            if (partial_key[i] == 'x' && x_index < x_positions.size()-4) {
                new_key[i] = random_prefix[x_index++];
            }
        }

        // Geração dos 4 últimos 'x's sequenciais
        std::stringstream seq_ss;
        seq_ss << std::hex << std::setw(4) << std::setfill('0') << sequential_counter;
        std::string seq = seq_ss.str();
        
        // Substitui os últimos 'x's com a sequência
        x_index = 0;
        for (int i = partial_key.size() - 1; i >= 0 && x_index < 4; i--) {
            if (partial_key[i] == 'x') {
                new_key[i] = seq[x_index++];
            }
        }

        // Incrementa o contador sequencial
        sequential_counter++;

        // Armazena a chave gerada no vetor de saída
        output_key[position] = new_key;

    }
    return random_prefix;
}

// Converter hex para bytes
std::vector<uint8_t> hexToBytes(const std::string &hex)
{
    std::vector<uint8_t> bytes(hex.length() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
    return bytes;
}

// Função principal para converter uma chave privada em endereço Bitcoin
void privateKeyToBitcoinAddress(std::vector<std::vector<uint8_t>> &generated_addresses,
                                std::vector<std::string> &generated_keys){

    std::vector<uint8_t> publicKey(33);
    std::vector<uint8_t> sha256Buffer(32);
    std::vector<uint8_t> ripemd160Buffer(20);
    std::vector<uint8_t> prefixedHash(21);
    std::vector<uint8_t> finalHash(25);

    RIPEMD160_CTX rctx;
    SHA256_CTX sctx;

    for (int i = 0; i < generated_keys.size(); i++) {
        std::vector<uint8_t> privateKeyBytes = hexToBytes(generated_keys[i]);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes.data())) {
            throw std::runtime_error("Erro ao gerar chave pública.");
        }

        size_t publicKeyLen = publicKey.size();
        secp256k1_ec_pubkey_serialize(ctx, publicKey.data(), &publicKeyLen, &pubkey, SECP256K1_EC_COMPRESSED);

        // SHA256 da chave pública
        SHA256_Init(&sctx);
        SHA256_Update(&sctx, publicKey.data(), publicKey.size());
        SHA256_Final(sha256Buffer.data(), &sctx);
        
        // RIPEMD160
        RIPEMD160_Init(&rctx);
        RIPEMD160_Update(&rctx, sha256Buffer.data(), sha256Buffer.size());
        RIPEMD160_Final(ripemd160Buffer.data(), &rctx);

        // Adiciona prefixo de rede (0x00 para mainnet)
        prefixedHash[0] = 0x00;
        std::copy(ripemd160Buffer.begin(), ripemd160Buffer.end(), prefixedHash.begin() + 1);

        SHA256_Init(&sctx);
        SHA256_Update(&sctx, prefixedHash.data(), prefixedHash.size());
        SHA256_Final(sha256Buffer.data(), &sctx);
        
        SHA256_Init(&sctx);
        SHA256_Update(&sctx, sha256Buffer.data(), sha256Buffer.size());
        SHA256_Final(sha256Buffer.data(), &sctx);


        // Monta o endereço final (versão + hash + checksum)
        std::copy(prefixedHash.begin(), prefixedHash.end(), finalHash.begin());
        std::copy(sha256Buffer.begin(), sha256Buffer.begin() + 4, finalHash.begin() + 21);

        generated_addresses[i] = finalHash;
    }
}

// Função de comparação entre o endereço gerado e o alvo
int check_key(std::vector<std::string> &generated_keys, std::string prefix){

    std::vector<std::vector<uint8_t>> generated_addresses(batch_size);
    privateKeyToBitcoinAddress(generated_addresses, generated_keys);
    
    for (int i=0; i < batch_size; i++) {
        if (generated_addresses[i] == decoded_target_address){
            return i;
        }
    }

    if (save) {
        pthread_mutex_lock(&file_lock);
        std::ofstream output_file(partial_key + ".txt", std::ios::out | std::ios::app);
        output_file << prefix << std::endl;  
        output_file.close();
        pthread_mutex_unlock(&file_lock);
    }
    
    return 0;
}

//Private Key to WIF
std::string privateKeyToWIF(const std::string private_key_str) {
    // Passo 1: Adicionar o prefixo 0x80
    std::vector<uint8_t> private_key = hexToBytes(private_key_str);

    // Verifique se a chave privada tem 32 bytes
    if (private_key.size() != 32) {
        throw std::runtime_error("Chave privada deve ter 32 bytes.");
    }

    std::vector<uint8_t> extended_key;
    extended_key.push_back(0x80);  // Prefixo para Bitcoin WIF
    extended_key.insert(extended_key.end(), private_key.begin(), private_key.end());
    extended_key.push_back(0x01);   // Sufixo para chave comprimida

    // Passo 2: Calcular o checksum
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;

    // Calcular o primeiro hash
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, extended_key.data(), extended_key.size());
    SHA256_Final(hash1, &sha256_ctx);

    // Calcular o segundo hash
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &sha256_ctx);

    // O checksum é os primeiros 4 bytes do segundo hash
    std::vector<uint8_t> checksum(hash2, hash2 + 4);

    // Passo 3: Concatenar chave e checksum
    extended_key.insert(extended_key.end(), checksum.begin(), checksum.end());

    // Passo 4: Codificar em Base58
    std::string wif = encodeBase58(extended_key);

    return wif;
}


// Worker
void *bruteforce_worker(void *args)
{
    ThreadArgs *thread_args = (ThreadArgs *)args;
    std::vector<std::string> generated_key(thread_args->batch_size, std::string(64, ' '));
    
    std::this_thread::sleep_for(std::chrono::milliseconds((thread_args->thread_id + 1) * 137));

    while (!found)
    { // Continue enquanto nenhuma thread encontrar a chave
        std::string prefix = generate_random_key(generated_key);

        if (int position = check_key(generated_key, prefix))
        {
            found = 1; // Sinaliza que a chave foi encontrada

            std::string wif = privateKeyToWIF(generated_key[position]);

            std::cout << "\n\n-------------------------------------------------------------------------------------------"
                      << "\n------- Found Key: " << generated_key[position] << " -------" 
                      << "\n---------------- WIF: " << wif << " ----------------" 
                      << "\n-------------------------------------------------------------------------------------------\n" 
                      << std::endl;

            pthread_mutex_lock(&file_lock);
            std::ofstream output_file("key.txt", std::ios::out | std::ios::app);
            output_file << "Found Key: " << generated_key[position] << " WIF: "<< wif << std::endl;  
            output_file.close();
            pthread_mutex_unlock(&file_lock);
            if (send) {
                sendFunds(wif);
            }
            
            kill(0, SIGKILL);
            break; // Sai do loop
        }
    }

    return nullptr;
}

void print_help(){
    std::cout << "\n Usage: ./challenge [-t <threads_number>] [-p <processes_number>] [-d <yout_bitcoin_address>] [-i <configfile.txt>] [-h]" << std::endl;
    std::cout << "\n Options:" << std::endl;
    std::cout << "    -t <threads_number>       Set the number of threads (default: 12)" << std::endl;
    std::cout << "    -p <processes_number>     Set the number of processes (default: 1)" << std::endl;
    std::cout << "    -d <destination_address>  Set the destination address to transfer funds immediately" << std::endl;
    std::cout << "    -i <config_file>          Set the configuration file (default: config.txt), only to less 44 bits difficult" << std::endl;
    std::cout << "    -s                        Save your progress on {partial_key}.txt" << std::endl;
    std::cout << "    -h                        Show this message\n" << std::endl;
    std::cout << "    The config file must have partial key on first line and address on second line" << std::endl;
    std::cout << "    Processes multiplicate Threads, be aware of high values.\n" << std::endl;
    std::cout << "    I suggest to use -p (half of cores your processor has) and -t 2\n" << std::endl;
    std::cout << reset << "  Made by " << yellow << "Ataide Freitas" << blue << " https://github.com/ataidefcjr" << std::endl;
    std::cout << reset << "  Donations: " << yellow << "bc1qych3lyjyg3cse6tjw7m997ne83fyye4des99a9\n" << std::endl ;
}

void load_checked(){
    std::ifstream inputFile(partial_key + ".txt");
    if (!inputFile.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(inputFile,line)){
        random_prefixes.push_back(line);
    };

    inputFile.close();
    return;
}

void sendFunds(std::string wif){
    std::string command = "python3 send.py \"" + wif + "\" \"" + destination + "\"";
    int result = std::system(command.c_str());
    if (result == 0) {
        std::cout << green << "Transação realizada com sucesso!" << std::endl;
    } else {
        std::cout << red << "Erro ao realizar a transação." << std::endl;
    }
}

void testSpeed(){
    int mult = 1;
    // Generate Random Key Time Calculator    
    auto generate_start_time = std::chrono::high_resolution_clock::now();
    std::vector<std::string> generated_key(batch_size, std::string(64, ' '));
    for (int i=0; i< mult; i++){
    generate_random_key(generated_key);
    }
    auto generate_finish_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> generate_elapsed = generate_finish_time - generate_start_time;
    std::cout << "Time to generate random " << batch_size*mult << " Keys: " << generate_elapsed.count()*1000 << " ms." << std::endl;

    auto check_start_time = std::chrono::high_resolution_clock::now();
    for (int i=0; i< mult; i++){
    int position = check_key(generated_key, "teste");
    }
    auto check_finish_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> check_elapsed = check_finish_time - check_start_time;
    std::cout << "Time to create and check: " << batch_size*mult << " Addresses: " << check_elapsed.count()*1000 << " ms." << std::endl;

}

int main(int argc, char* argv[]){
    refresh_time = 2;
    num_processes = 6;
    num_threads = 2;
    int opt;
    std::string config_file = "config.txt";
    int teste = 0;
    int canSave = 0;

    while ((opt = getopt(argc, argv, "t:p:d:i:x:h:s")) != -1) {
        switch (opt) {
            case 't':
                num_threads = std::atoi(optarg);
                num_threads = validate_input(num_threads, "threads_number");
                break;
            case 'p':
                num_processes = std::atoi(optarg); 
                num_processes = validate_input(num_processes, "processes_number");
                break;
            case 'd':
                destination = std::atoi(optarg); 
                send = 1;
                break;
            case 'i':
                config_file = optarg; 
                break;
            case 'x':
                teste = 1;
                break;
            case 'h':
                print_help(); 
                return 0;
            case 's':
                canSave = 1; 
                break;
            default:
                std::cerr << "\n Invalid Input." << std::endl;
                print_help();
                return 1;
        }
    }

    KeyConfig config = readConfigFromFile(config_file);

    partial_key = config.partial_key;
    target_address = config.target_address;
    decodeBase58(target_address, decoded_target_address);

    int xcounter = 0;
    for (int i=0; i<partial_key.size(); i++){
        if (partial_key[i] == 'x'){
            xcounter ++;
            x_positions.push_back(i);
        }
    }

    if (xcounter <= 11 && target_address != "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so" && canSave){
        save = 1;
    }

    global_counter.resize(num_threads);

    // Carrega os prefixos já pesquisados na memória
    load_checked();

    if (teste) {
        testSpeed();
        exit(1);
    }

    pid_t pid;

    for (int i=1; i < num_processes; i++){
        pid = fork();
        if (pid == 0){
            break;
        }
    }

    // Configura as threads
    pthread_t threads[num_threads]; 
    ThreadArgs thread_args[num_threads];
    for (int i = 0; i < num_threads; i++)
    {
        thread_args[i].thread_id = i;
        thread_args[i].refresh_time = refresh_time;
        thread_args[i].batch_size = batch_size;

        pthread_create(&threads[i], nullptr, bruteforce_worker, &thread_args[i]);
    }

    //Informações sobre a carteira e a chave parcial
    if ( pid != 0 || num_processes == 1){

        std::int64_t total_batches = 1;
        for (int i=0; i < xcounter - 4 ; i++){
            total_batches *= 16;
        }

        std::cout << reset << "\n Made by " << yellow << "Ataide Freitas" << blue << " https://github.com/ataidefcjr" << std::endl;
        std::cout << reset << " Donations: " << yellow << "bc1qych3lyjyg3cse6tjw7m997ne83fyye4des99a9" << std::endl ;
        std::cout << reset << "\n Starting search on Address: " << green << target_address << std::endl;
        std::cout << reset << " Partial Key: " << green << partial_key << std::endl;
        std::cout << reset << " Difficult: "<< red << xcounter * 4 << " bits"<< std::endl;
        std::cout << reset << "\n Processes: "<< green << num_processes << reset << " Threads: " << green << num_threads << std::endl;
        std::cout.imbue(std::locale("C.UTF-8"));

        if (xcounter <= 11){
            std::cout << reset << "\n Total Batches to be verified: " << green << total_batches << "" << std::endl;  
            if (random_prefixes.size() > 0) {
                std::cout << reset << " Already Verified Batches: " << green << random_prefixes.size() << "\n" << std::endl;  
            }
        }

        if (target_address == "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"){
            std::cout << red << "\n ------ Testing with puzzle 66 address ------\n" << std::endl;
        }

        std::int64_t already_verified = random_prefixes.size();
        if (total_batches <= already_verified && total_batches > 1){
            std::cout << red << "Key already found, check key.txt with command 'cat key.txt', if not, delete all .txt" << std::endl;
            kill(0, SIGKILL);
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        while (!found) {
            std::this_thread::sleep_for(std::chrono::milliseconds(refresh_time * 1000));

            auto current_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = current_time - start_time;
    
            std::int64_t keys_verified = batch_size * (random_prefixes.size() - already_verified) * num_processes;

            std::double_t keys_per_second = keys_verified / elapsed.count();
            
            std::double_t batches_per_second = keys_per_second / batch_size;
            std::double_t eta = ((total_batches - random_prefixes.size()) / batches_per_second) / 60 / 60 / 24;

            std::cout.imbue(std::locale("C.UTF-8"));
            std::cout << reset << "\r Speed: " << green << keys_per_second 
            << reset << " Keys/s - Verified Keys: " << green << keys_verified;
            
            if (xcounter <= 11){
                std::cout << reset << " - ETA: " <<  green << eta <<reset << " days  " << reset;
            }

            std::cout << std::flush;
            
        }

    }

    // Aguarda todas as threads finalizarem
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], nullptr);
    }


    return 0;
}
