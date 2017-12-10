import os
import sys
from git import Repo

sys.path.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "..")))

from fame.common.constants import VENDOR_ROOT

def git_clone(url, name):
    decoders_path = os.path.join(VENDOR_ROOT, name)

    if os.path.exists(decoders_path):
        repo = Repo(decoders_path)
        repo.remotes.origin.pull()
    else:
        Repo.clone_from(url, decoders_path)

def main():
    git_clone("https://github.com/Yara-Rules/rules.git", "Yara-Rules")

if __name__ == '__main__':
    main()
