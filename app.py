import requests
import yaml


def load_config(path):
    with open(path) as f:
        return yaml.load(f.read(), Loader=yaml.SafeLoader)


def fetch(url):
    return requests.get(url).json()


if __name__ == "__main__":
    print(load_config("config.yml"))
