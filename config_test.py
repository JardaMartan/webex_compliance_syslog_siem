from dotenv import load_dotenv, find_dotenv
from pathlib import Path  # python3 only

env_path = Path('.') / '.env_test'
load_dotenv(dotenv_path=env_path, verbose=True)

if __name__ == '__main__':
    pass
