import hashlib
import multiprocessing
import os
import random
import time
import signal
from collections import deque
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from bloom_filter import BloomFilter
from multiprocessing import Value, Lock

# Конфигурация ключа
KEY_BITS = 69
TOTAL_KEYS = 2 ** KEY_BITS

# Конкретный адрес для поиска
TARGET_ADDRESS = '19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG'

# Функция для генерации закрытых ключей из целого числа
def generate_key_from_int(n):
    key = ECC.construct(d=n, curve='P-256')
    private_key = key.export_key(format='DER')
    public_key = key.public_key().export_key(format='DER')
    return private_key, public_key

# Функция преобразования открытого ключа в биткойн-адрес
def public_key_to_address(public_key):
    sha256 = SHA256.new(public_key)
    ripemd160 = hashlib.new('ripemd160', sha256.digest()).digest()
    return ripemd160.hex()

# Функция для проверки, является ли адрес целью
def is_target_address(address):
    return address == TARGET_ADDRESS

# Основная функция случайного поиска с эвристикой и счетчиком
def search_wallet_randomly(start, end, key_count_global, lock, bloom_filter, reservoir):
    try:
        while True:
            # Применение эвристики для генерации ключа
            random_key = start + random.getrandbits(KEY_BITS // 2) * random.choice([1, 2, 4, 8, 16])
            random_key = random_key % TOTAL_KEYS
            
            # Проверяет, был ли ключ уже использован с помощью Bloom Filter
            if random_key in bloom_filter:
                continue
            
            private_key, public_key = generate_key_from_int(random_key)
            address = public_key_to_address(public_key)

            # Пометьте ключ как используемый
            bloom_filter.add(random_key)
            reservoir.append((private_key, public_key))

            with lock:
                key_count_global.value += 1

            # Проверить, является ли адрес целью
            if is_target_address(address):
                with open("адрес_найден.txt", "w") as f:
                    f.write(f"Приватный ключ: {private_key.hex()}\n")
                    f.write(f"Публичный ключ: {public_key.hex()}\n")
                    f.write(f"Адрес: {address}\n")
                print(f"Адрес найден: {address}")
                os._exit(0)  # Немедленно останавливает скрипт при обнаружении кошелька
    except Exception as e:
        print(f"Ошибка в процессе: {e}")

# Функция для отображения общего прогресса каждые 60 секунд
def log_progress(key_count_global, start_time, lock):
    try:
        while True:
            time.sleep(60)
            elapsed_time = time.time() - start_time
            with lock:
                keys_processed = key_count_global.value
            keys_per_second = keys_processed / elapsed_time
            print(f"Ключей: {keys_processed}, {keys_per_second:.2f} keys/second")
    except Exception as e:
        print(f"Ошибка: нет журнала: {e}")

# Роль для управления пулом процессов
def parallel_search(num_processes, bloom_filter, reservoir):
    processes = []

    def start_processes():
        chunk_size = TOTAL_KEYS // num_processes
        for i in range(num_processes):
            start = i * chunk_size
            end = (i + 1) * chunk_size - 1
            if i == num_processes - 1:
                end = TOTAL_KEYS - 1  # Убедитесь, что последний процесс идет до конца

            process = multiprocessing.Process(target=search_wallet_randomly, args=(start, end, key_count_global, lock, bloom_filter, reservoir))
            processes.append(process)
            process.start()

    # Начать процесс регистрации
    start_time = time.time()
    log_process = multiprocessing.Process(target=log_progress, args=(key_count_global, start_time, lock))
    log_process.start()

    start_processes()

    def shutdown(sig, frame):
        print("Завершение всех процессов...")
        for process in processes:
            process.terminate()
        log_process.terminate()
        print("Все процессы были прекращены.")
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)

    while True:
        for process in processes:
            if not process.is_alive():
                processes.remove(process)
                print("Перезапуск процесса, который не удался...")
                start_processes()

if __name__ == "__main__":
    # Фиксирует объем оперативной памяти и потоков, которые пользователь хочет использовать
    ram_gb = int(input("Сколько ГБ оперативной памяти вы хотите использовать: "))
    threads = int(input("Сколько потоков (ядер ЦП) вы хотите использовать: "))

    # Настройки фильтра Блума для предотвращения дублирования ключей
    estimated_elements = (ram_gb * 10**7)  # Оценка на основе желаемого объема оперативной памяти
    false_positive_rate = 0.001  # 0,1% частота ошибок
    bloom_filter = BloomFilter(max_elements=estimated_elements, error_rate=false_positive_rate)

    # Глобальная переменная для подсчета обработанных ключей
    key_count_global = Value('i', 0)
    lock = Lock()

    # Конфигурация резервуара как deque
    reservoir = deque(maxlen=100)

    parallel_search(threads, bloom_filter, reservoir)
