import requests
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f.read())


def fetch(url):
    return requests.get(url).json()


if __name__ == "__main__":
    print(load_config("config.yml"))
