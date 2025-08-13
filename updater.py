import requests, zipfile, io, os

GITHUB_VERSION_URL = "https://raw.githubusercontent.com/dr0pnet/dr0pnet-honeypot/main/version.txt"
GITHUB_ZIP_URL = "https://github.com/dr0pnet/dr0pnet-honeypot/raw/main/dr0pnet-honeypot.zip"
LOCAL_VERSION_FILE = "version.txt"

def get_local_version():
    if not os.path.exists(LOCAL_VERSION_FILE):
        return "0.0.0"
    with open(LOCAL_VERSION_FILE, "r") as f:
        return f.read().strip()

def get_remote_version():
    response = requests.get(GITHUB_VERSION_URL)
    return response.text.strip()

def download_and_extract():
    print("[+] Downloading update ZIP...")
    r = requests.get(GITHUB_ZIP_URL)
    with zipfile.ZipFile(io.BytesIO(r.content)) as zip_ref:
        zip_ref.extractall(".")
    print("[+] Update installed!")

def main():
    local = get_local_version()
    remote = get_remote_version()
    print(f"Local: {local} | Remote: {remote}")
    if local != remote:
        print("[+] New version found. Updating...")
        download_and_extract()
        with open(LOCAL_VERSION_FILE, "w") as f:
            f.write(remote)
    else:
        print("[✓] Already up to date.")

if __name__ == "__main__":
    main()
